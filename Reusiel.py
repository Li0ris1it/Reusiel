#!/usr/bin/python3
from neo4j import GraphDatabase
import argparse
import json
from collections import Counter
import re

def username_variants_initial_full_only(parts, seps=(".", "_", "-", ""," ")):
    """
    parts: ['first','last']
    returns: sorted list of variants like:
      raphaeld, draphael, rdiaz, diazr,
      r.diaz, diaz.r, raphael.d, d.raphael, etc.
    """
    first = parts[0].lower().strip() if parts and parts[0] else ""
    last  = parts[1].lower().strip() if len(parts) > 1 and parts[1] else ""
    if not first or not last:
        return []

    fi, li = first[0], last[0]
    out = set()

    # no separator
    out.add(first + li)   # raphaeld
    out.add(li + first)   # draphael
    out.add(fi + last)    # rdiaz
    out.add(last + fi)    # diazr

    # with separators
    for s in seps:
        out.add(f"{first}{s}{li}")  # raphael.d
        out.add(f"{li}{s}{first}")  # d.raphael
        out.add(f"{fi}{s}{last}")   # r.diaz
        out.add(f"{last}{s}{fi}")   # diaz.r
        out.add(f"{first}{s}{last}")  # raphael.diaz / raphael_diaz / raphael-diaz / raphaeldiaz
        out.add(f"{last}{s}{first}")  # diaz.raphael / diaz_raphael / diaz-raphael / diazraphael

    # (optional) ensure minimum length >= 3
    return sorted(x for x in out if len(x) >= 3)


def searcher(candidates, username, password, uri):
  #get domain sid
#  try:
    #domainsid_query= "Match (d:Domain) where tolower(d.name) = $domain return d.domainsid"
    #domain_sid= driver.session.run(domainsid_query, domain=domain_input.lower()).data()
#  except:
#    print("connection error or no data returned from query")
  results_list=[]
  queries = ["Match (u:User) where tolower(u.displayname) = $name return u.name,u.displayname", "Match (u:User) where tolower(u.name) = $name return u.name", "Match (u:User) where tolower(u.samaccountname) = $name return u.name,u.samaccountname","Match (u:User) where tolower(u.email) contains $name return u.name,u.email", "Match (u:User) where tolower(u.description) contains $name return u.name,u.description" ]
#  cypher =""

#  props = ["name", "displayname", "samaccountname", "email", "title", "description"]
#  props = ["title","description","email"]
#  exact_props = ["displayname","samaccountname"]
#  weights = {"name": 3, "samaccountname": 3, "displayname": 3, "email": 2, "title": 1, "description":1}
  driver = GraphDatabase.driver(uri, auth=(username, password))
  for name in candidates:
#    print("looking for " +name + " in bloodhound") 
    for query in queries:
      results= driver.session().run(query, name=name,).data()
      if results:
        results_list.append(results)
  driver.close()
  filtered_list = list(filter(None, results_list))
  return filtered_list


def summarize_and_print(flat):
    """
    Prints:
      - duplicate counts by u.name
      - unique result objects (first occurrence per u.name)
    Returns:
      (seen_unique_map, usernames_set)
        seen_unique_map: dict[u.name] -> row
        usernames_set: set of normalized USER names (uppercased, no domain)
    """
    # dup counts
    names = [r.get("u.name") for r in flat if "u.name" in r]
    counts = Counter(names)
    print("=== Duplicate Counts ===")
    dups = [f"{n}: {c}" for n, c in counts.items() if c > 1]
    print("\n".join(dups) if dups else "(no duplicates)")

    # uniques (keep first)
    seen = {}
    for r in flat:
        seen.setdefault(r.get("u.name"), r)

    print("\n=== Unique Results ===")
    for r in seen.values():
        print(json.dumps(r))

    # normalized usernames
    usernames = set()
    for uname in seen.keys():
        if not uname:
            continue
        s = str(uname)
        if "@" in s:      # user@domain
            s = s.split("@", 1)[0]
        if "\\" in s:     # DOMAIN\user
            s = s.split("\\", 1)[-1]
        usernames.add(s.upper())

    return seen, usernames


def build_username_pattern(usernames):
    """
    Build a single regex that matches:
      USER, USER_history, USER_history<digits>
    Returns compiled pattern or None if usernames empty.
    """
    if not usernames:
        return None
    patt = r"\b(?:%s)\b" % "|".join(
        fr"{re.escape(u)}(?:_history\d*)?" for u in sorted(usernames)
    )
    return re.compile(patt, re.IGNORECASE)


def scan_file_and_print(file_path, pattern, cut_fields=(1, 4), delimiter=":"):
    """
    Scans file, for each matching line prints the equivalent of:
      cut -d ':' -f1,4   (configurable via cut_fields & delimiter)
    Avoids printing duplicate output lines.
    """
    if not (file_path and pattern):
        return
    printed = set()
    f1, f2 = cut_fields
    i1, i2 = f1 - 1, f2 - 1

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if pattern.search(line):
                parts = line.split(delimiter)
                out = f"{parts[i1]}{delimiter}{parts[i2]}" if max(i1, i2) < len(parts) else line
                if out not in printed:
                    print(out)
                    printed.add(out)

def main():
  parser = argparse.ArgumentParser(description='fdfdn')
  parser.add_argument("-dbp", help="bloodhound password", dest="password", default="bloodhoundcommunityedition")
  parser.add_argument("-i", help="uri of neo4j", dest="uri",default="bolt://localhost:7687")
#  parser.add_argument("-d", help="domain we own ", dest="domain_input")
  parser.add_argument("-dbu", help="bloodhound username", dest="username",default="neo4j")
  parser.add_argument("-u", help="user to look for ", dest="user_input")
  parser.add_argument("-f", "--file", help="path to raw NTDS file to scan for usernames")
  args = parser.parse_args()
  candidates = username_variants_initial_full_only(args.user_input.split(" "))
  #print(searcher(candidates, args.username, args.password, args.uri))
  results = searcher(candidates, args.username, args.password, args.uri)
  flat = [item for sublist in results for item in sublist]
  seen, usernames = summarize_and_print(flat)
  if args.file and usernames:
      pattern = build_username_pattern(usernames)
      print("\n=== File Matches (just like cutty cutty 4 dolla) ===")
      before = True
      scan_file_and_print(args.file, pattern, cut_fields=(1, 4), delimiter=":")


if __name__ == "__main__":
    main()
 

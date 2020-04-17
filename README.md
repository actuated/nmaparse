# nmaparse
Revised shell script for parsing .gnmap or .xml Nmap files to a CSV list, lists of IPs per port, web urls, and a summary table.

# usage
```
./nmaparse.sh [source file] [--out-dir [path]]
```
- **[source file]** specifies the input file. The script will detect whether it's .gnmap or .xml based on whether `/open/` or `port protocol=` can be found.
- **[--out-dir [path]]** optionally specifies an output directory other than the default nmaparse-YYYY-MM-DD-HH-MM.

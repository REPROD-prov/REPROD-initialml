RADIX / SPADE Time Slices

This is how to produce time slice dot files from Procmon XML files (i.e., they've been converted to from the initial
PML format, details on the [SPADE wiki](https://github.com/ashish-gehani/SPADE/wiki/Collecting-system-wide-provenance-on-Windows). Follow the instructions below, substituting {PROCMONLOGS_DIR, DATA_DIR, RANSOMWARE.XML} as needed:

1.  Set up the SPADE environment

In a terminal window (call this terminal window 1):

```
$ docker pull sricsl/radix:0.3
$ docker run -it -v PROCMONLOGS_DIR:/spade-logs:ro  -v DATA_DIR:/spade-data sricsl/radix:0.3
# bin/spade start
# bin/manage-quickstep.sh start --path /tmp/quickstep-database
# bin/spade control
-> add storage Quickstep
-> add reporter ProcMon input=/spade-logs/RANSOMWARE.XML
-> add analyzer CommandLine
-> exit
```

2.  Make file with all of the edges.

```
# bin/spade query
-> set storage Quickstep
-> list
```

Note: repeat the list command above until the Number of Vertices and Edges doesn't change for at least 10 minutes.

```
-> env unset exportLimit
-> $edges = $base.getEdge()
-> export > /spade-data/RANSOMWARE-edges.dot
-> dump all $edges
-> exit
```

3.  Determine Procmon data start and stop time.

In another terminal window::
> slice-data/find_datetimes.py DATA_DIR/RANSOMWARE-edges.dot

You will see something like:
"2/22/2022 1:34:56 AM" "2/22/2022 2:09:20 AM"

4.  Produce query file for SPADE.
Staying in terminal window 2:
> mkdir DATA_DIR/RANSOMWARE
> chmod 777 DATA_DIR/RANSOMWARE
> slice-data/slice_data.py <start and end times from above including quotes> DATA_DIR/REvil.sh /spade-data/RANSOMWARE

You will see a count, such as:
`total count:  2065`

Then:
`> chmod 666 DATA_DIR/RANSOMWARE.sh`

5.  Input query file to SPADE query.
Moving back to terminal 1:
`# bin/spade query < DATA_DIR/RANSOMWARE.sh`

6.  Confirm all time slice files created.
Remaining in terminal 1:
# cd DATA_DIR/RANSOMWARE
# ls | wc

Note:  first number should match total count from slice_data.py

7.  Use ^D to exit docker.


____________________________________________________________________________________________________


This is how to produce time slice per process dot files from Procmon XML files.  This assumes you want to time slice the data in PROCMONLOGS_DIR/RANSOMWARE.XML and store the time slice files in directory DATA_DIR/RANSOMWARE.  Follow the instructions below, substituting file names as needed:

1.  Set up the SPADE environment again,

```
$ docker pull sricsl/radix:0.3

$ docker run -it -v  PROCMONLOGS_DIR:/spade-logs:ro  -v DATA_DIR:/spade-data2 sricsl/radix:0.3

$bin/spade start

$ bin/manage-quickstep.sh start --path /tmp/quickstep-database
bin/spade control
add storage Quickstep
add reporter ProcMon input=/spade-logs/RANSOMWARE.XML
add analyzer CommandLine
exit
```

2.  Make file with all of the processes and edges.

```
bin/spade query
set storage Quickstep
list
```
Note: repeat the list command above until the Number of Vertices and Edges doesn't change for at least 10 minutes.
```
env unset exportLimit
$all_processes = $base.getVertex(type == 'Process')
export > /spade-data2/RANSOMWARE-processes.dot
dump all $all_processes
$all_edges = $base.getEdge()
export > /spade-data2/RANSOMWARE-edges.dot
dump all $all_edges
exit
```

3.  Produce query file for SPADE.
In another terminal window (call this terminal window 2):
> slice-data/slice_processes.py REv

You will see:
100 processes found
200 timeslices found

4.  Input query file to SPADE query.
Moving back to terminal 1:
# bin/spade query < /spade-data2/RANSOMWARE.sh

5.  Confirm all time slice files created.
Remaining in terminal 1:
# cd /spade-data2/RANSOMWARE
# find . -type f | wc -l

Note:  number should match timeslices count from step 3

6.  Use ^D to exit docker.

____________________________________________________________________________________________________

An archive of our 20 initial samples is provided in `mldata.tar.xz`.  We haven't provided all the
documentation, but users can see how we implemented regex based matching to classify timeslice data
from ransomware runs. This can be unzipped with

`unzip -F mldata.zip`
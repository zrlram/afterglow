AfterGlow
=========

Change Log
----------
09/08/14     Version 1.6.5 - Two Node Mode
             - If the first line of the input only has two columns,  twonode mode is set automatically
             - The default edge length is now set to 1.5 instead of the old 3, which should make for 
               more compact graphs by default
07/08/13     Version 1.6.4 - GraphSON support
             - Adding GraphSON data format support for tools like Helios.js
                -j       : on the command line
                or
                graphson = 1 : in property file
            - Fixing event node size regex check
04/30/13     Version 1.6.3 - Minor edits - Removal of additional scripts
             - This version is the first one not to bundle the sample data, perl scripts, and log analysis scripts anymore
               Find them on github at: http://github.com/zrlram/parsers and
                                       https://github.com/zrlram/loganalysis
             - Fixed issue with color names
             - Added xlabels by default. This way, labels are displayed outside of the node itself, not
               inside anymore. You can turn this off by using
                 xlabels = 0
               in the configuration file.
             - Fixing output bug where target printed twice
10/16/11     Version 1.6.2 - GDF support
             - Removed afterglow-lgl.pl finally. Sorry, but I don't think anyone is using LGL anymore
               anyways. Get it from CVS if you need it.
             - Adding GDF data format support for tools like Gephi.
                -k      : on the command line
                or
                gdf = 1 : in property file
12/02/10    Version 1.6.1 - Paul Halliday patch
            - Adding new shape: Mrecord
            - Adding new meta information. You can now input 5 columns where the last two or three
              (depending on whether you are in two or three column mode) are meta data that you can
              use in the configuration file.
03/22/10	Version 1.6.0
		    - Adding edge sizes
			    (size.edge=<expression returning size>)
		      Default edge size is one. No scaling is done! Sizes are absolute!
		    - Fixing a bug with the "not a color" message. Should only show if some
		      color was actually set
  		    - label.(source|event|target)=0 now turns off labels for real.
		    - Added a DEBUG variable
		    - New command line functions:
			    -q      : Quiet mode. Suppress all output. Attention!
 			              You should use -w to write output to a file!
			    -i file : Read input from a file, instead of from STDIN
 			    -w file : Write output to a file, instead of to STDOUT
            - Adding get_severity() function for configuration files. (By request from Paul Halliday)
                color.source=get_severity($fields[2])
                color.source=get_severity($fields[0],20)
                Second, optional argument, is for the maximum number of steps. The highest
                severity is red, the lowest is green, the ones inbetween shades.

07/30/08	Version 1.5.9.5 - DAVIX special release
		- Deleted experimental scripts:
			- afterglow-lgl2.pl
			- afterglow-walrus.pl
		- Removing debug statements from afterglow code
		- Fixing various little issues in afterglow (see source for more information)
		- Allowing hex numbers as colors (new graphviz feature)

09/08/07	Version 1.5.9
		- Adding property to add a URL element to nodes. See sample.properties for an example.
		- Adding label property to change labels on nodes. This overwrites the old
			label.(source|event|destination) to use not only boolean values.
			If you are using [0|1] it turns labels on or off. Otherwise it uses the
			expression as the label
		- New is also that you can define "label" which defines the label for all the nodes

06/10/07	Version 1.5.8
		- Nodes can have a size now:
			  (size.[source|target|event]=<expression returning size>)
		  Size is accumulative! So if a node shows up multiple times, the
		  values are summed up!! This is unlike any other property in
		  AfterGlow where values are replaced.
		- The maximum node size can be defined as well, either with a
		  property:
			  (maxnodesize=<value>)
		  or via the command line:
			  -m=<value>
		  The size is scaled to a max of 'maxsize'. Note that if you
		  are only setting the maxsize and no special sizes for nodes
		  Afterglow will blow the nodes up to optimal size so the labels
		  will fit.
		  There is a limit also, if you want the source nodes to be a max of say
		  1, you cannot have the target nodes be scaled to fit the labels. They
		  will have a max size of 1 and if you don't use any expression, they will
		  be of size 1. This can be a bit annoying ;)
		  Be cautious with sizes. The number you provide in the assignment is not the actual size
		  that the node will get, but this number will get scaled!
		- One of the problems with assignments is that they might get overwritten with later nodes
		  For example, you have these entries:
		  	A,B
			A,C
		  and your properties are:
		  	color="blue" if ($fileds[1] eq "B")
			color="red"
		  you would really expect the color for A to be blue as you specified that explicitly.
		  However, as the other entry comes later, the color will end up being red. AfterGlow takes
		  care of this. It will determine that the second color assignment is a catch-all, identified
		  by the fact that there is no "if" statement. If this happens, it will re-use the more specific
		  condition specified earlier. I hope I am making sense and the code really does what you would
		  expect ;)
		- Define whether AfterGlow should sum node sizes or not.
		  (sum.[source|target|event]=[0|1];)
		  by default summarization is enabled.
		- Added capability to define thresholds per node type in properties file
		  (threshold.[source|event|target]=<value>;)
		- Added capability to change the node shape:
			shape.[source|event|target]=
			    (box|polygon|circle|ellipse|invtriangle|octagon|pentagon|diamond|point|triangle|plaintext)
		- Fixed an issue where, if you use -t to only process two columns
		  and you can use the third in the property file for size or color.
		  The third column was not carried through, however. This is fixed!
		- The color assignment heuristic changed a bit. Along the same lines that the size assignment works.
		  Catch-alls are not taking presedence anymore. You might want to take this into account when defining
		  colors. The catch-all will only be used, if there was never a more specific color assignment that
		  was evaluated for this node. For example:
			color="gray50" if ($fields[2] !~ /(CON|FIN|CLO)/)
			color="white"
		  This is used with a three-column dataset, but only two are displayed (-t). If the first condition
		  ever evaluated to true for a node, the last one will not hit, although the data might have a node that
		  evaluates to false in the first assignment and then the latter one would grip. As a catch-all it does
		  get superior treatment. This is really what you would intuitively assume.
		- Just another note on color. Watch out, if you are definig colors not based on the fields in the
		  data, but some other conditions that might change per record, you will get the wrong results as
		  AfterGlow uses a cache for colorswhich keys off the concatenation of all the field values. Just
		  a note! Anyone having problems with this? I might have to change the heuristic for caching then. Let
		  me know.

02/08/07	Version 1.5.7
		- With this release I am not bundling the scripts in the
		  database directory anymore. Get them from CVS if you
		  need them.
		- Adding label to the graph (-a command line option)
		- Color nodes which are source AND target differently
		  (color.sourcetarget=...)
		- Added Text::CSV to parse input data (Thanks Neil)

07/03/06	Version 1.5.6
		- Fan out filtering introduced
		- Introducing subnet() function
		- Introducing field() function
		- Code optimization for speedup!
		- Configuration option to define variables (variable=)
		- Removed regex() operator (duplicate of match())
		- Fixed a few bugs for clustering

03/09/06	Version 1.4
		- Fixing omit-threshold bug. Only draw edges if BOTH nodes
		  have a higher threshold, not just one of them.
		- Introducing cluster capability. This will cluster
		  multiple nodes into one;
 		      cluster=expression
			      cluster.{source,event,target}=expression
		- Introduction of functions to work with colors and
		  clusters:
		      any_regex()
		      regex()
		      match()
		      regex_replace()

03/05/06	Version 1.3
		- Adding capability to define colors independent
		  of the node (color=...)
		- Introducing label.{source,event,target}=[0|1]
		  to disable labels


Graphing Scripts (afterglow/src/perl/graph)
----------------

This is where the AfterGlow 1.x scripts are located:

afterglow-lgl.pl	(AfterGlow-LGL, generates LGL output)
afterglow.pl		(AfterGlow, generates GraphViz output)
color.properties	(Example color.properties file for AfterGlow)

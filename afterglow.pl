#!/usr/bin/perl
#
# Copyright (c) 2013 by Raffael Marty and Christian Beedgen
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#  
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# Written by:    Christian Beedgen (krist@digitalresearch.org)
#                Raffael Marty (ram@cryptojail.net)
#
# Version:    1.6.3
#
# URL:        http://afterglow.sourceforge.net
#
# Sample Usage:
#         tcpdump -vttttnnelr /home/ram/defcon.07.31.10.14.tcpdump.1 | 
#         ./tcpdump2csv.pl "sip dip ttl" | ../graph/afterglow.pl 
#         -c /home/ram/color.defcon.properties -p 2 | neato -Tgif -o test.gif
# 
# Okay, simpler:
#         cat file.csv | perl afterglow.pl | neato -Tgif -o test.gif
#
# ChangeLog:    
#
# 1.1        Adding option to omit node labels    
# 1.1.1        Adding option to color nodes
# 1.1.2        Adding option to make nodes invisible
# 1.1.3        Adding option to eliminate one to one edges (omit threshold)
# 1.1.4        Adding option to show node counts
# 1.1.5        Adding option to color edges
# 1.1.6        Fixing node counts for non-common event nodes
# 1.2        Refining labels: Instead of just setting them globally, allow for 
#         setting them per node type. Also if no label is applied, the node 
#         should be smaller
#         Making event nodes smaller by default
# 1.3        Adding capability to define colors independant
#         of the node (color=...)
#        Introducing label.{source,event,targate}=[0|1] to disable labels
# 1.4        Clustering Nodes together into one cluster
#         cluster=expression
#        cluster.{source,event,target}=expression
#        Functions: any_regex()
#               regex()
#               match()
#               regex_replace()
#        Functions work for clusters and colors!
#        Fixing omit-threshold bug. Only draw edges if BOTH nodes have
#        a higher threshold, not just one of them.
# 1.5        Adding GNU license. Finally!
#         Playing with fan-out filtering (introducing -f and -g command line switches)
#        Indicating line number where error occured in property file
#        Adding "exit" property file entry to stop processing
#        Fixing property file parsing to be more flexible (bug in regex: s to \s)
#        Fixing annoyance with "no color assigned" errors, assign default colors 
#        if not explicitely set in property file.
# 1.5.1        Making parsing of property file a bit more flexible
#        Adding subnet() function
#        Adding field() function, returning the current field value
#        Adding version information to usage();
#        Fixing error message "not a color: " that showed all the time
#          it was checking edge colors when they were not even defined
#        Don't evaluate clusters, if no clusters defined.
#        Trying to do some code optimization by checking whether
#          a certain feature is needed
#        Doing some optimization by intorudcing a color cache! MUCH faster!
#        TBD: Introduce a cluster cache!
#        TBD: Are there variables that can be omitted by using others?
# 1.5.2        There was a bug for the event fan out threshold which would cause
#         that the source nodes would not be drawn with the -g option!
# 1.5.3        There was a bug when you use -p 1 and -f 1. The source nodes
#         are eliminated for clusters that should not show, but the rest of the 
#         nodes were still drawn!
# 1.5.4        New configuration option: variable. Code in this assignment will be 
#         executed in the beginning and can be used to boot-strap variables
# 1.5.5        The invisible color check needs to be after clustering!
# 1.5.6        Fixing bug that match() would not work in the color assignment
#         Basically globalField was not set.
#        Removed regex() function. match() is doing the same thing ... Duh...
# 1.5.7        Adding label to the graph : -a option, enabled by default
#        Color nodes which are sources and targets at the same time with a specific
#        color. A new property in the properties file:
#            color.sourcetarget=...
#        This was something I had planned before and Neil Desai pushed me a bit to
#        finally get it done. 
#        Neil Desai contributed a couple of lines of code to use Text::CSV to do 
#            safe CSV parsing. Thanks!
# 1.5.8        Allowing size on nodes to be configured!
#             size.[source|target|event]=<perl returning integer>
#        Option to define the maximum node size on command line (-m <value>)
#            maxnodesize=<value> also defines the maximum node size, but in 
#        the property file. See README for more information on sizing.
#        Define whether AfterGlow should automatically sum nodes or not.
#            sum.[source|target|event]=[0|1];
#            By default scaling is disabled.
#        Added capability to define thresholds per node type in properties file
#            threshold.[source|event|target]=<threshold>;
#        Added capability for changing the node shape:
#            shape.[source|event|target]=
#                (box|polygon|circle|ellipse|invtriangle|octagon|pentagon|diamond|point|triangle|plaintext)
#        Removed semicolon at end of every line in property file.
#        Updated description for -o action in usage().
#        Updated the link to the graphviz project.
#        Coloring bug with source/target nodes
#            Along the way I changed the semantics a bit:
#            - source color wins over target color for sourc/target nodes,
#              if the source/target color is not set!
#            - "color" wins over source and target color for source/target nodes, if 
#              the source/target color is not set!
#        I did some research around edge sizes. Sorry, graphviz does not support it.
#        Label color was never implemented. Fixed
#        Fixing a bug related to sourcetarget colors. The variable had a capital T.
#            This should make the "not a color:" error go away!
#        Added new heuristic to determine color. A catch-all assignment will not be considered
#        if there was a more specific assignment that was possible. See README for more details.
# 1.5.9        Adding property to add a URL element to nodes. See sample.properties for an example.
#        Adding label property to change labels on nodes. This overwrites the old 
#            label.(source|event|target) to use not only boolean values.
#            If you are using [0|1] it turns labels on or off. Otherwise it uses the 
#            expression as the label
#        New is also that you can define "label" which defines the label for all the nodes
# 1.6.0  If you had quote around the shape value, it would not recignize it. Fixed.
#         label.(source|event|target)=0 now turns off labels for real.
#        Adding edge thickness:
#            size.edge=<perl returning integer>
#            Note that the sizes are absolute! No scaling done!
#            The default edge size is 1
#        Another fix for the "not a color:" error. Only scream if a color as actually set
#        New command line functions:
#            -q      : Quiet mode. Suppress all output. Attention! 
#            -i file : Read input from a file, instead of from STDIN
#            -w file : Write output to a file, instead of to STDOUT
#        Adding new get_severity function for configs to color based on a severity:
#           color.source=get_severity($fields[2])
#           color.source=get_severity($fields[0],20)
#           Second, optional argument, is for the maximum number of steps. The highest
#           severity is red, the lowest is green, the ones inbetween shades.
# 1.6.1  Patch from Paul Halliday:
#        Adding new shape: Mrecord
#        Adding new meta information. You can now input 5 columns where the last two or three
#        (depending on whether you are in two or three column mode) are meta data that you can
#        use in the configuration file.
# 1.6.2  Adding GDF output format:
#           gdf = true
#        Or:
#           -k on commandline
#        Fixing some variable names. Size should really be fanout. Nicer code.
#        Changed the order that edges and nodes are output. Because of the GDF format, we first
#        process the edges and then output the nodes and then after hat output the edges. DOT does
#        not care about the oder, but GDF does, so we change the output sequence. We cannot 
#        reorder the code for nodes and egdes as the nodes depend on variables that are computed
#        by the edges, so we cache the data
# 1.6.3  Fixing a couple of issues. 
#           color.source="#222222" wasn't working
#           -x "#222222" wasn't working on command line
#        Adding xlabels for graphviz output (in config file:) - This is now true by default
#           xlabels = true
#        Fixing a bug where the target name is printed twice (Thanks Mark Schloesser for reporting)
#	     Fixing import path for Text::CSV to be local
# 	     Fixing copyright. Sorry Christian!
#    
##############################################################

# ------------------------------------------------------------
# Main program.
# ------------------------------------------------------------

# include the lib directory right here for Text::CSV
use FindBin qw($Bin);
use lib "$FindBin::Bin/.";

# Program version
my $version = "1.6.3";

use Text::CSV;
my $csvline = Text::CSV->new();

# Whether or not verbose mode is enabled.
# A value of '1' indicates that verbose mode is enabled.
# By default, verbose mode is disabled.
my $verbose = 0;

my $DEBUG = 0;

# output format in GML or DOT?
my $gdf = 0;

# use xlabels in output? On by default!
my $xlabels = 1;

# Whether or not to split source and target nodes.
# A value of '1' indicates that the nodes will be split.
# Any other value means the nodes will not be split.
my $splitSourceAndTargetNodes = 0;

# Split mode for event nodes.
my $eventNodeSplitMode = 0;

# The number of lines to skip before starting to read.
my $skipLines = 0;

# Two node mode (objects are skipped).
my $twonodes = 0;

# The maximum number of lines to read.
my $maxLines = 999999;

# Print node labels? (yes by default)
my $nodeLabels = 1;

# source node label?
$sourceLabel=1;

# target node label?
$targetLabel=1;

# event node label?
$eventLabel=1;

# default edge length
my $edgelen = 3;

# default label color
my $labelColor = "black";

# default edge size
my $defaultEdgeSize = 1;

# invisible color
my $invisibleColor = "invisible";

# default color for GDF format
my $defaultColor = "'100,100,100'";

# Ommit node-count. 1 means that every node with a count of 1 or smaller is not drawn!
my $omitThreshold = 0;
my $sourceThreshold = 0;
my $targetThreshold = 0;
my $eventThreshold = 0;

# Fan out of nodes to omit. 1 means that every node with a fan out of one is omitted.
my $sourceFanOutThreshold = 0;

# Fan out of nodes to omit. 1 means that every node with a fan out of one is omitted.
my $eventFanOutThreshold = 0;

# Clustering Nodes?     name -> regex
my @clusters;
my @source_clusters;
my @event_clusters;
my @target_clusters;

# Print Node Count
my $nodeCount = 0;

# Edge Style
my $edgeStyle = "solid";

# Maximum Node Size, default is 0.2
my $maxNodeSize = 0.2;
# Don't want any division by zero ;)
my $maxActualSourceNodeSize = 1;
my $maxActualTargetNodeSize = 1;
my $maxActualEventNodeSize = 1;

# Disabling summary of sizes by default
my $sumSource = 0;
my $sumTarget = 0;
my $sumEvent = 0;

my $shapeSource = "ellipse";
my $shapeTarget = "ellipse";
my $shapeEvent = "ellipse";

# URL for nodes, off by default
my $url=0;

# Process commandline options.
&init;

# Echo options if verbose.
print STDERR "Verbose mode is on.\n" if $verbose;
print STDERR "Skipping $skipLines lines.\n" if $verbose;
print STDERR "Reading a maximum of $maxLines lines.\n" if $verbose;
print STDERR "Two node mode (objects are skipped.\n" if $verbose && $twonodes;
print STDERR "Splitting source and target nodes.\n" if $verbose && $splitSourceAndTargetNodes;
print STDERR "Split mode for events is $eventNodeSplitMode.\n" if $verbose;
print STDERR "Threshold $omitThreshold.\n" if $verbose;
print STDERR "Source Threshold $sourceThreshold.\n" if $verbose;
print STDERR "Target Threshold $targetThreshold.\n" if $verbose;
print STDERR "Event Threshold $eventThreshold.\n" if $verbose;
print STDERR "Maximum Node Size $maxNodeSize.\n" if $verbose;
# TBD: Add new options!
print STDERR "\n" if $verbose;

&propertyfile;

# the color map
%colorIndex = ();
$colorIndexCount=1;
@colors=qw{aliceblue antiquewhite antiquewhite1 antiquewhite2
antiquewhite3 antiquewhite4 aquamarine aquamarine1 aquamarine2 aquamarine3
aquamarine4 azure azure1 azure2 azure3 azure4 beige bisque bisque1
bisque2 bisque3 bisque4 black blanchedalmond blue blue1 blue2 blue3
blue4 blueviolet brown brown1 brown2 brown3 brown4 burlywood burlywood1
burlywood2 burlywood3 burlywood4 cadetblue cadetblue1 cadetblue2
cadetblue3 cadetblue4 chartreuse chartreuse1 chartreuse2 chartreuse3
chartreuse4 chocolate chocolate1 chocolate2 chocolate3 chocolate4
coral coral1 coral2 coral3 coral4 cornflowerblue cornsilk cornsilk1
cornsilk2 cornsilk3 cornsilk4 crimson cyan cyan1 cyan2 cyan3 cyan4
darkgoldenrod darkgoldenrod1 darkgoldenrod2 darkgoldenrod3 darkgoldenrod4
darkgreen darkkhaki darkolivegreen darkolivegreen1 darkolivegreen2
darkolivegreen3 darkolivegreen4 darkorange darkorange1 darkorange2
darkorange3 darkorange4 darkorchid darkorchid1 darkorchid2 darkorchid3
darkorchid4 darksalmon darkseagreen darkseagreen1 darkseagreen2
darkseagreen3 darkseagreen4 darkslateblue darkslategray darkslategray1
darkslategray2 darkslategray3 darkslategray4 darkslategrey darkturquoise
darkviolet deeppink deeppink1 deeppink2 deeppink3 deeppink4 deepskyblue
deepskyblue1 deepskyblue2 deepskyblue3 deepskyblue4 dimgray dimgrey
dodgerblue dodgerblue1 dodgerblue2 dodgerblue3 dodgerblue4 firebrick
firebrick1 firebrick2 firebrick3 firebrick4 floralwhite forestgreen
gainsboro ghostwhite gold gold1 gold2 gold3 gold4 goldenrod goldenrod1
goldenrod2 goldenrod3 goldenrod4 gray gray0 gray1 gray10 gray100 gray11
gray12 gray13 gray14 gray15 gray16 gray17 gray18 gray19 gray2 gray20
gray21 gray22 gray23 gray24 gray25 gray26 gray27 gray28 gray29 gray3
gray30 gray31 gray32 gray33 gray34 gray35 gray36 gray37 gray38 gray39
gray4 gray40 gray41 gray42 gray43 gray44 gray45 gray46 gray47 gray48
gray49 gray5 gray50 gray51 gray52 gray53 gray54 gray55 gray56 gray57
gray58 gray59 gray6 gray60 gray61 gray62 gray63 gray64 gray65 gray66
gray67 gray68 gray69 gray7 gray70 gray71 gray72 gray73 gray74 gray75
gray76 gray77 gray78 gray79 gray8 gray80 gray81 gray82 gray83 gray84
gray85 gray86 gray87 gray88 gray89 gray9 gray90 gray91 gray92 gray93
gray94 gray95 gray96 gray97 gray98 gray99 green green1 green2 green3
green4 greenyellow grey grey0 grey1 grey10 grey100 grey11 grey12 grey13
grey14 grey15 grey16 grey17 grey18 grey19 grey2 grey20 grey21 grey22
grey23 grey24 grey25 grey26 grey27 grey28 grey29 grey3 grey30 grey31
grey32 grey33 grey34 grey35 grey36 grey37 grey38 grey39 grey4 grey40
grey41 grey42 grey43 grey44 grey45 grey46 grey47 grey48 grey49 grey5
grey50 grey51 grey52 grey53 grey54 grey55 grey56 grey57 grey58 grey59
grey6 grey60 grey61 grey62 grey63 grey64 grey65 grey66 grey67 grey68
grey69 grey7 grey70 grey71 grey72 grey73 grey74 grey75 grey76 grey77
grey78 grey79 grey8 grey80 grey81 grey82 grey83 grey84 grey85 grey86
grey87 grey88 grey89 grey9 grey90 grey91 grey92 grey93 grey94 grey95
grey96 grey97 grey98 grey99 honeydew honeydew1 honeydew2 honeydew3
honeydew4 hotpink hotpink1 hotpink2 hotpink3 hotpink4 indianred
indianred1 indianred2 indianred3 indianred4 indigo ivory ivory1 ivory2
ivory3 ivory4 khaki khaki1 khaki2 khaki3 khaki4 lavender lavenderblush
lavenderblush1 lavenderblush2 lavenderblush3 lavenderblush4 lawngreen
lemonchiffon lemonchiffon1 lemonchiffon2 lemonchiffon3 lemonchiffon4
lightblue lightblue1 lightblue2 lightblue3 lightblue4 lightcoral
lightcyan lightcyan1 lightcyan2 lightcyan3 lightcyan4 lightgoldenrod
lightgoldenrod1 lightgoldenrod2 lightgoldenrod3 lightgoldenrod4
lightgoldenrodyellow lightgray lightgrey lightpink lightpink1 lightpink2
lightpink3 lightpink4 lightsalmon lightsalmon1 lightsalmon2 lightsalmon3
lightsalmon4 lightseagreen lightskyblue lightskyblue1 lightskyblue2
lightskyblue3 lightskyblue4 lightslateblue lightslategray lightslategrey
lightsteelblue lightsteelblue1 lightsteelblue2 lightsteelblue3
lightsteelblue4 lightyellow lightyellow1 lightyellow2 lightyellow3
lightyellow4 limegreen linen magenta magenta1 magenta2 magenta3 magenta4
maroon maroon1 maroon2 maroon3 maroon4 mediumaquamarine mediumblue
mediumorchid mediumorchid1 mediumorchid2 mediumorchid3 mediumorchid4
mediumpurple mediumpurple1 mediumpurple2 mediumpurple3 mediumpurple4
mediumseagreen mediumslateblue mediumspringgreen mediumturquoise
mediumvioletred midnightblue mintcream mistyrose mistyrose1 mistyrose2
mistyrose3 mistyrose4 moccasin navajowhite navajowhite1 navajowhite2
navajowhite3 navajowhite4 navy navyblue oldlace olivedrab olivedrab1
olivedrab2 olivedrab3 olivedrab4 orange orange1 orange2 orange3 orange4
orangered orangered1 orangered2 orangered3 orangered4 orchid orchid1
orchid2 orchid3 orchid4 palegoldenrod palegreen palegreen1 palegreen2
palegreen3 palegreen4 paleturquoise paleturquoise1 paleturquoise2
paleturquoise3 paleturquoise4 palevioletred palevioletred1 palevioletred2
palevioletred3 palevioletred4 papayawhip peachpuff peachpuff1 peachpuff2
peachpuff3 peachpuff4 peru pink pink1 pink2 pink3 pink4 plum plum1 plum2
plum3 plum4 powderblue purple purple1 purple2 purple3 purple4 red red1
red2 red3 red4 rosybrown rosybrown1 rosybrown2 rosybrown3 rosybrown4
royalblue royalblue1 royalblue2 royalblue3 royalblue4 saddlebrown salmon
salmon1 salmon2 salmon3 salmon4 sandybrown seagreen seagreen1 seagreen2
seagreen3 seagreen4 seashell seashell1 seashell2 seashell3 seashell4
sienna sienna1 sienna2 sienna3 sienna4 skyblue skyblue1 skyblue2 skyblue3
skyblue4 slateblue slateblue1 slateblue2 slateblue3 slateblue4 slategray
slategray1 slategray2 slategray3 slategray4 slategrey snow snow1
snow2 snow3 snow4 springgreen springgreen1 springgreen2 springgreen3
springgreen4 steelblue steelblue1 steelblue2 steelblue3 steelblue4
tan tan1 tan2 tan3 tan4 thistle thistle1 thistle2 thistle3 thistle4
tomato tomato1 tomato2 tomato3 tomato4 transparent turquoise turquoise1
turquoise2 turquoise3 turquoise4 violet violetred violetred1 violetred2
violetred3 violetred4 wheat wheat1 wheat2 wheat3 wheat4 white invisible};

my %color_to_rgb_map = (
    "indianred"=>"177,23,31", "crimson"=>"220,20,60", "lightpink"=>"255,182,193",
    "lightpink1"=>"255,174,185", "lightpink2"=>"238,162,173", "lightpink3"=>"205,140,149",
    "lightpink4"=>"139,95,101", "pink"=>"255,192,203", "pink1"=>"255,181,197",
    "pink2"=>"238,169,184", "pink3"=>"205,145,158", "pink4"=>"139,99,108",
    "palevioletred"=>"219,112,147", "palevioletred1"=>"255,130,171", "palevioletred2"=>"238,121,159",
    "palevioletred3"=>"205,104,137", "palevioletred4"=>"139,71,93", "lavenderblush"=>"255,240,245",
    "lavenderblush1"=>"255,240,245", "lavenderblush2"=>"238,224,229", "lavenderblush3"=>"205,193,197",
    "lavenderblush4"=>"139,131,134", "violetred1"=>"255,62,150", "violetred2"=>"238,58,140",
    "violetred3"=>"205,50,120", "violetred4"=>"139,34,82", "hotpink"=>"255,105,180",
    "hotpink1"=>"255,110,180", "hotpink2"=>"238,106,167", "hotpink3"=>"205,96,144",
    "hotpink4"=>"139,58,98", "raspberry"=>"135,38,87", "deeppink"=>"255,20,147",
    "deeppink1"=>"255,20,147", "deeppink2"=>"238,18,137", "deeppink3"=>"205,16,118",
    "deeppink4"=>"139,10,80", "maroon1"=>"255,52,179", "maroon2"=>"238,48,167",
    "maroon3"=>"205,41,144", "maroon4"=>"139,28,98", "mediumvioletred"=>"199,21,133",
    "violetred"=>"208,32,144", "orchid"=>"218,112,214", "orchid1"=>"255,131,250",
    "orchid2"=>"238,122,233", "orchid3"=>"205,105,201", "orchid4"=>"139,71,137",
    "thistle"=>"216,191,216", "thistle1"=>"255,225,255", "thistle2"=>"238,210,238",
    "thistle3"=>"205,181,205", "thistle4"=>"139,123,139", "plum1"=>"255,187,255",
    "plum2"=>"238,174,238", "plum3"=>"205,150,205", "plum4"=>"139,102,139",
    "plum"=>"221,160,221", "violet"=>"238,130,238", "magenta"=>"255,0,255",
    "fuchsia"=>"255,0,255", "magenta2"=>"238,0,238", "magenta3"=>"205,0,205",
    "magenta4"=>"139,0,139", "darkmagenta"=>"139,0,139", "purple"=>"128,0,128",
    "mediumorchid"=>"186,85,211", "mediumorchid1"=>"224,102,255", "mediumorchid2"=>"209,95,238",
    "mediumorchid3"=>"180,82,205", "mediumorchid4"=>"122,55,139", "darkviolet"=>"148,0,211",
    "darkorchid"=>"153,50,204", "darkorchid1"=>"191,62,255", "darkorchid2"=>"178,58,238",
    "darkorchid3"=>"154,50,205", "darkorchid4"=>"104,34,139", "indigo"=>"75,0,130",
    "blueviolet"=>"138,43,226", "purple1"=>"155,48,255", "purple2"=>"145,44,238",
    "purple3"=>"125,38,205", "purple4"=>"85,26,139", "mediumpurple"=>"147,112,219",
    "mediumpurple1"=>"171,130,255", "mediumpurple2"=>"159,121,238", "mediumpurple3"=>"137,104,205",
    "mediumpurple4"=>"93,71,139", "darkslateblue"=>"72,61,139", "lightslateblue"=>"132,112,255",
    "mediumslateblue"=>"123,104,238", "slateblue"=>"106,90,205", "slateblue1"=>"131,111,255",
    "slateblue2"=>"122,103,238", "slateblue3"=>"105,89,205", "slateblue4"=>"71,60,139",
    "ghostwhite"=>"248,248,255", "lavender"=>"230,230,250", "blue"=>"0,0,255",
    "blue2"=>"0,0,238", "blue3"=>"0,0,205", "mediumblue"=>"0,0,205",
    "blue4"=>"0,0,139", "darkblue"=>"0,0,139", "navy"=>"0,0,128",
    "midnightblue"=>"25,25,112", "cobalt"=>"61,89,171", "royalblue"=>"65,105,225",
    "royalblue1"=>"72,118,255", "royalblue2"=>"67,110,238", "royalblue3"=>"58,95,205",
    "royalblue4"=>"39,64,139", "cornflowerblue"=>"100,149,237", "lightsteelblue"=>"176,196,222",
    "lightsteelblue1"=>"202,225,255", "lightsteelblue2"=>"188,210,238", "lightsteelblue3"=>"162,181,205",
    "lightsteelblue4"=>"110,123,139", "lightslategray"=>"119,136,153", "slategray"=>"112,128,144",
    "slategray1"=>"198,226,255", "slategray2"=>"185,211,238", "slategray3"=>"159,182,205",
    "slategray4"=>"108,123,139", "dodgerblue1"=>"30,144,255", "dodgerblue"=>"30,144,255",
    "dodgerblue2"=>"28,134,238", "dodgerblue3"=>"24,116,205", "dodgerblue4"=>"16,78,139",
    "aliceblue"=>"240,248,255", "steelblue"=>"70,130,180", "steelblue1"=>"99,184,255",
    "steelblue2"=>"92,172,238", "steelblue3"=>"79,148,205", "steelblue4"=>"54,100,139",
    "lightskyblue"=>"135,206,250", "lightskyblue1"=>"176,226,255", "lightskyblue2"=>"164,211,238",
    "lightskyblue3"=>"141,182,205", "lightskyblue4"=>"96,123,139", "skyblue1"=>"135,206,255",
    "skyblue2"=>"126,192,238", "skyblue3"=>"108,166,205", "skyblue4"=>"74,112,139",
    "skyblue"=>"135,206,235", "deepskyblue1"=>"0,191,255", "deepskyblue"=>"0,191,255",
    "deepskyblue2"=>"0,178,238", "deepskyblue3"=>"0,154,205", "deepskyblue4"=>"0,104,139",
    "peacock"=>"51,161,201", "lightblue"=>"173,216,230", "lightblue1"=>"191,239,255",
    "lightblue2"=>"178,223,238", "lightblue3"=>"154,192,205", "lightblue4"=>"104,131,139",
    "powderblue"=>"176,224,230", "cadetblue1"=>"152,245,255", "cadetblue2"=>"142,229,238",
    "cadetblue3"=>"122,197,205", "cadetblue4"=>"83,134,139", "turquoise1"=>"0,245,255",
    "turquoise2"=>"0,229,238", "turquoise3"=>"0,197,205", "turquoise4"=>"0,134,139",
    "cadetblue"=>"95,158,160", "darkturquoise"=>"0,206,209", "azure1"=>"240,255,255",
    "azure"=>"240,255,255", "azure2"=>"224,238,238", "azure3"=>"193,205,205",
    "azure4"=>"131,139,139", "lightcyan1"=>"224,255,255", "lightcyan"=>"224,255,255",
    "lightcyan2"=>"209,238,238", "lightcyan3"=>"180,205,205", "lightcyan4"=>"122,139,139",
    "paleturquoise1"=>"187,255,255", "paleturquoise2"=>"174,238,238", "paleturquoise"=>"174,238,238",
    "paleturquoise3"=>"150,205,205", "paleturquoise4"=>"102,139,139", "darkslategray"=>"47,79,79",
    "darkslategray1"=>"151,255,255", "darkslategray2"=>"141,238,238", "darkslategray3"=>"121,205,205",
    "darkslategray4"=>"82,139,139", "cyan"=>"0,255,255", "cyan2"=>"0,238,238",
    "cyan3"=>"0,205,205", "cyan4"=>"0,139,139", "darkcyan"=>"0,139,139",
    "teal"=>"0,128,128", "mediumturquoise"=>"72,209,204", "lightseagreen"=>"32,178,170",
    "manganeseblue"=>"3,168,158", "turquoise"=>"64,224,208", "coldgrey"=>"128,138,135",
    "turquoiseblue"=>"0,199,140", "aquamarine1"=>"127,255,212", "aquamarine"=>"127,255,212",
    "aquamarine2"=>"118,238,198", "aquamarine3"=>"102,205,170", "mediumaquamarine"=>"102,205,170",
    "aquamarine4"=>"69,139,116", "mediumspringgreen"=>"0,250,154", "mintcream"=>"245,255,250",
    "springgreen"=>"0,255,127", "springgreen1"=>"0,238,118", "springgreen2"=>"0,205,102",
    "springgreen3"=>"0,139,69", "mediumseagreen"=>"60,179,113", "seagreen1"=>"84,255,159",
    "seagreen2"=>"78,238,148", "seagreen3"=>"67,205,128", "seagreen4"=>"46,139,87",
    "seagreen"=>"46,139,87", "emeraldgreen"=>"0,201,87", "mint"=>"189,252,201",
    "cobaltgreen"=>"61,145,64", "honeydew1"=>"240,255,240", "honeydew"=>"240,255,240",
    "honeydew2"=>"224,238,224", "honeydew3"=>"193,205,193", "honeydew4"=>"131,139,131",
    "darkseagreen"=>"143,188,143", "darkseagreen1"=>"193,255,193", "darkseagreen2"=>"180,238,180",
    "darkseagreen3"=>"155,205,155", "darkseagreen4"=>"105,139,105", "palegreen"=>"152,251,152",
    "palegreen1"=>"154,255,154", "palegreen2"=>"144,238,144", "lightgreen"=>"144,238,144",
    "palegreen3"=>"124,205,124", "palegreen4"=>"84,139,84", "limegreen"=>"50,205,50",
    "forestgreen"=>"34,139,34", "green1"=>"0,255,0", "lime"=>"0,255,0",
    "green2"=>"0,238,0", "green3"=>"0,205,0", "green4"=>"0,139,0",
    "green"=>"0,128,0", "darkgreen"=>"0,100,0", "sapgreen"=>"48,128,20",
    "lawngreen"=>"124,252,0", "chartreuse1"=>"127,255,0", "chartreuse"=>"127,255,0",
    "chartreuse2"=>"118,238,0", "chartreuse3"=>"102,205,0", "chartreuse4"=>"69,139,0",
    "greenyellow"=>"173,255,47", "darkolivegreen1"=>"202,255,112", "darkolivegreen2"=>"188,238,104",
    "darkolivegreen3"=>"162,205,90", "darkolivegreen4"=>"110,139,61", "darkolivegreen"=>"85,107,47",
    "olivedrab"=>"107,142,35", "olivedrab1"=>"192,255,62", "olivedrab2"=>"179,238,58",
    "olivedrab3"=>"154,205,50", "yellowgreen"=>"154,205,50", "olivedrab4"=>"105,139,34",
    "ivory1"=>"255,255,240", "ivory"=>"255,255,240", "ivory2"=>"238,238,224",
    "ivory3"=>"205,205,193", "ivory4"=>"139,139,131", "beige"=>"245,245,220",
    "lightyellow1"=>"255,255,224", "lightyellow"=>"255,255,224", "lightyellow2"=>"238,238,209",
    "lightyellow3"=>"205,205,180", "lightyellow4"=>"139,139,122", "lightgoldenrodyellow"=>"250,250,210",
    "yellow1"=>"255,255,0", "yellow"=>"255,255,0", "yellow2"=>"238,238,0",
    "yellow3"=>"205,205,0", "yellow4"=>"139,139,0", "warmgrey"=>"128,128,105",
    "olive"=>"128,128,0", "darkkhaki"=>"189,183,107", "khaki1"=>"255,246,143",
    "khaki2"=>"238,230,133", "khaki3"=>"205,198,115", "khaki4"=>"139,134,78",
    "khaki"=>"240,230,140", "palegoldenrod"=>"238,232,170", "lemonchiffon1"=>"255,250,205",
    "lemonchiffon"=>"255,250,205", "lemonchiffon2"=>"238,233,191", "lemonchiffon3"=>"205,201,165",
    "lemonchiffon4"=>"139,137,112", "lightgoldenrod1"=>"255,236,139", "lightgoldenrod2"=>"238,220,130",
    "lightgoldenrod3"=>"205,190,112", "lightgoldenrod4"=>"139,129,76", "banana"=>"227,207,87",
    "gold1"=>"255,215,0", "gold"=>"255,215,0", "gold2"=>"238,201,0",
    "gold3"=>"205,173,0", "gold4"=>"139,117,0", "cornsilk1"=>"255,248,220",
    "cornsilk"=>"255,248,220", "cornsilk2"=>"238,232,205", "cornsilk3"=>"205,200,177",
    "cornsilk4"=>"139,136,120", "goldenrod"=>"218,165,32", "goldenrod1"=>"255,193,37",
    "goldenrod2"=>"238,180,34", "goldenrod3"=>"205,155,29", "goldenrod4"=>"139,105,20",
    "darkgoldenrod"=>"184,134,11", "darkgoldenrod1"=>"255,185,15", "darkgoldenrod2"=>"238,173,14",
    "darkgoldenrod3"=>"205,149,12", "darkgoldenrod4"=>"139,101,8", "orange1"=>"255,165,0",
    "orange"=>"255,165,0", "orange2"=>"238,154,0", "orange3"=>"205,133,0",
    "orange4"=>"139,90,0", "floralwhite"=>"255,250,240", "oldlace"=>"253,245,230",
    "wheat"=>"245,222,179", "wheat1"=>"255,231,186", "wheat2"=>"238,216,174",
    "wheat3"=>"205,186,150", "wheat4"=>"139,126,102", "moccasin"=>"255,228,181",
    "papayawhip"=>"255,239,213", "blanchedalmond"=>"255,235,205", "navajowhite1"=>"255,222,173",
    "navajowhite"=>"255,222,173", "navajowhite2"=>"238,207,161", "navajowhite3"=>"205,179,139",
    "navajowhite4"=>"139,121,94", "eggshell"=>"252,230,201", "tan"=>"210,180,140",
    "brick"=>"156,102,31", "cadmiumyellow"=>"255,153,18", "antiquewhite"=>"250,235,215",
    "antiquewhite1"=>"255,239,219", "antiquewhite2"=>"238,223,204", "antiquewhite3"=>"205,192,176",
    "antiquewhite4"=>"139,131,120", "burlywood"=>"222,184,135", "burlywood1"=>"255,211,155",
    "burlywood2"=>"238,197,145", "burlywood3"=>"205,170,125", "burlywood4"=>"139,115,85",
    "bisque1"=>"255,228,196", "bisque"=>"255,228,196", "bisque2"=>"238,213,183",
    "bisque3"=>"205,183,158", "bisque4"=>"139,125,107", "melon"=>"227,168,105",
    "carrot"=>"237,145,33", "darkorange"=>"255,140,0", "darkorange1"=>"255,127,0",
    "darkorange2"=>"238,118,0", "darkorange3"=>"205,102,0", "darkorange4"=>"139,69,0",
    "orange"=>"255,128,0", "tan1"=>"255,165,79", "tan2"=>"238,154,73",
    "tan3"=>"205,133,63", "peru"=>"205,133,63", "tan4"=>"139,90,43",
    "linen"=>"250,240,230", "peachpuff1"=>"255,218,185", "peachpuff"=>"255,218,185",
    "peachpuff2"=>"238,203,173", "peachpuff3"=>"205,175,149", "peachpuff4"=>"139,119,101",
    "seashell1"=>"255,245,238", "seashell"=>"255,245,238", "seashell2"=>"238,229,222",
    "seashell3"=>"205,197,191", "seashell4"=>"139,134,130", "sandybrown"=>"244,164,96",
    "rawsienna"=>"199,97,20", "chocolate"=>"210,105,30", "chocolate1"=>"255,127,36",
    "chocolate2"=>"238,118,33", "chocolate3"=>"205,102,29", "chocolate4"=>"139,69,19",
    "saddlebrown"=>"139,69,19", "ivoryblack"=>"41,36,33", "flesh"=>"255,125,64",
    "cadmiumorange"=>"255,97,3", "burntsienna"=>"138,54,15", "sienna"=>"160,82,45",
    "sienna1"=>"255,130,71", "sienna2"=>"238,121,66", "sienna3"=>"205,104,57",
    "sienna4"=>"139,71,38", "lightsalmon1"=>"255,160,122", "lightsalmon"=>"255,160,122",
    "lightsalmon2"=>"238,149,114", "lightsalmon3"=>"205,129,98", "lightsalmon4"=>"139,87,66",
    "coral"=>"255,127,80", "orangered1"=>"255,69,0", "orangered"=>"255,69,0",
    "orangered2"=>"238,64,0", "orangered3"=>"205,55,0", "orangered4"=>"139,37,0",
    "sepia"=>"94,38,18", "darksalmon"=>"233,150,122", "salmon1"=>"255,140,105",
    "salmon2"=>"238,130,98", "salmon3"=>"205,112,84", "salmon4"=>"139,76,57",
    "coral1"=>"255,114,86", "coral2"=>"238,106,80", "coral3"=>"205,91,69",
    "coral4"=>"139,62,47", "burntumber"=>"138,51,36", "tomato1"=>"255,99,71",
    "tomato"=>"255,99,71", "tomato2"=>"238,92,66", "tomato3"=>"205,79,57",
    "tomato4"=>"139,54,38", "salmon"=>"250,128,114", "mistyrose1"=>"255,228,225",
    "mistyrose"=>"255,228,225", "mistyrose2"=>"238,213,210", "mistyrose3"=>"205,183,181",
    "mistyrose4"=>"139,125,123", "snow1"=>"255,250,250", "snow"=>"255,250,250",
    "snow2"=>"238,233,233", "snow3"=>"205,201,201", "snow4"=>"139,137,137",
    "rosybrown"=>"188,143,143", "rosybrown1"=>"255,193,193", "rosybrown2"=>"238,180,180",
    "rosybrown3"=>"205,155,155", "rosybrown4"=>"139,105,105", "lightcoral"=>"240,128,128",
    "indianred"=>"205,92,92", "indianred1"=>"255,106,106", "indianred2"=>"238,99,99",
    "indianred4"=>"139,58,58", "indianred3"=>"205,85,85", "brown"=>"165,42,42",
    "brown1"=>"255,64,64", "brown2"=>"238,59,59", "brown3"=>"205,51,51",
    "brown4"=>"139,35,35", "firebrick"=>"178,34,34", "firebrick1"=>"255,48,48",
    "firebrick2"=>"238,44,44", "firebrick3"=>"205,38,38", "firebrick4"=>"139,26,26",
    "red1"=>"255,0,0", "red"=>"255,0,0", "red2"=>"238,0,0",
    "red3"=>"205,0,0", "red4"=>"139,0,0", "darkred"=>"139,0,0",
    "maroon"=>"128,0,0", "sgibeet"=>"142,56,142", "sgislateblue"=>"113,113,198",
    "sgilightblue"=>"125,158,192", "sgiteal"=>"56,142,142", "sgichartreuse"=>"113,198,113",
    "sgiolivedrab"=>"142,142,56", "sgibrightgray"=>"197,193,170", "sgisalmon"=>"198,113,113",
    "sgidarkgray"=>"85,85,85", "sgigray12"=>"30,30,30", "sgigray16"=>"40,40,40",
    "sgigray32"=>"81,81,81", "sgigray36"=>"91,91,91", "sgigray52"=>"132,132,132",
    "sgigray56"=>"142,142,142", "sgilightgray"=>"170,170,170", "sgigray72"=>"183,183,183",
    "sgigray76"=>"193,193,193", "sgigray92"=>"234,234,234", "sgigray96"=>"244,244,244",
    "white"=>"255,255,255", "whitesmoke"=>"245,245,245", "gray96"=>"245,245,245",
    "gainsboro"=>"220,220,220", "lightgrey"=>"211,211,211", "silver"=>"192,192,192",
    "darkgray"=>"169,169,169", "gray"=>"128,128,128", "dimgray"=>"105,105,105",
    "gray42"=>"105,105,105", "black"=>"0,0,0", "gray99"=>"252,252,252",
    "gray98"=>"250,250,250", "gray97"=>"247,247,247", "whitesmoke"=>"245,245,245",
    "gray96"=>"245,245,245", "gray95"=>"242,242,242", "gray94"=>"240,240,240",
    "gray93"=>"237,237,237", "gray92"=>"235,235,235", "gray91"=>"232,232,232",
    "gray90"=>"229,229,229", "gray89"=>"227,227,227", "gray88"=>"224,224,224",
    "gray87"=>"222,222,222", "gray86"=>"219,219,219", "gray85"=>"217,217,217",
    "gray84"=>"214,214,214", "gray83"=>"212,212,212", "gray82"=>"209,209,209",
    "gray81"=>"207,207,207", "gray80"=>"204,204,204", "gray79"=>"201,201,201",
    "gray78"=>"199,199,199", "gray77"=>"196,196,196", "gray76"=>"194,194,194",
    "gray75"=>"191,191,191", "gray74"=>"189,189,189", "gray73"=>"186,186,186",
    "gray72"=>"184,184,184", "gray71"=>"181,181,181", "gray70"=>"179,179,179",
    "gray69"=>"176,176,176", "gray68"=>"173,173,173", "gray67"=>"171,171,171",
    "gray66"=>"168,168,168", "gray65"=>"166,166,166", "gray64"=>"163,163,163",
    "gray63"=>"161,161,161", "gray62"=>"158,158,158", "gray61"=>"156,156,156",
    "gray60"=>"153,153,153", "gray59"=>"150,150,150", "gray58"=>"148,148,148",
    "gray57"=>"145,145,145", "gray56"=>"143,143,143", "gray55"=>"140,140,140",
    "gray54"=>"138,138,138", "gray53"=>"135,135,135", "gray52"=>"133,133,133",
    "gray51"=>"130,130,130", "gray50"=>"127,127,127", "gray49"=>"125,125,125",
    "gray48"=>"122,122,122", "gray47"=>"120,120,120", "gray46"=>"117,117,117",
    "gray45"=>"115,115,115", "gray44"=>"112,112,112", "gray43"=>"110,110,110",
    "gray42"=>"107,107,107", "dimgray"=>"105,105,105", "gray42"=>"105,105,105",
    "gray40"=>"103,102,102", "gray39"=>"99,99,99", "gray38"=>"97,97,97",
    "gray37"=>"94,94,94", "gray36"=>"92,92,92", "gray35"=>"89,89,89",
    "gray34"=>"87,87,87", "gray33"=>"84,84,84", "gray32"=>"82,82,82",
    "gray31"=>"79,79,79", "gray30"=>"77,77,77", "gray29"=>"74,74,74",
    "gray28"=>"71,71,71", "gray27"=>"69,69,69", "gray26"=>"66,66,66",
    "gray25"=>"64,64,64", "gray24"=>"61,61,61", "gray23"=>"59,59,59",
    "gray22"=>"56,56,56", "gray21"=>"54,54,54", "gray20"=>"51,51,51",
    "gray19"=>"48,48,48", "gray18"=>"46,46,46", "gray17"=>"43,43,43",
    "gray16"=>"41,41,41", "gray15"=>"38,38,38", "gray14"=>"36,36,36",
    "gray13"=>"33,33,33", "gray12"=>"31,31,31", "gray11"=>"28,28,28",
    "gray10"=>"26,26,26", "gray9"=>"23,23,23", "gray8"=>"20,20,20",
    "gray7"=>"18,18,18", "gray6"=>"15,15,15", "gray5"=>"13,13,13",
    "gray4"=>"10,10,10", "gray3"=>"8,8,8", "gray2"=>"5,5,5",
    "gray1"=>"3,3,3"
);

# Bunch of associative arrays we will need.
%sourceMap = (); %eventMap = (); %targetMap = ();
%sourceEventLinkMap = (); %eventTargetLinkMap = ();
%sourceTargetLinkMap = {};
our (@sourceColorExp, @targetColorExp, @eventColorExp, @edgeColorExp, @sourcetargetColorExp);
# size of nodes
our (@sourceSizeExp,@targetSizeExp,@eventSizeExp);
# size of edges
our (@edgeSizeExp);
# labels of nodes
our (@sourceLabelExp,@targetLabelExp,@eventLabelExp);

# counting how many times the nodes show up
our (%sourceCount, %eventCount, %targetCount);
our %sourceFanOut = {};
our %eventFanOut = {};
# if fan out threshold are used, this hash is used to keep track of th enodes
# that need to be printed. Otherwise there are orphand nodes lingering in the graph
our %printNode = {};

# need this for the property functions
our $globalField;

# Write header.
if (!$gdf) {print "digraph structs {\n";}

# global parameters
if ($label && !$gdf) { 
    print "graph [label=\"AfterGlow ".$version;
    # if ($splitSourceAndTargetNodes) { print "split ";
    if ($eventNodeSplitMode) {print " - Split Mode: ".$eventNodeSplitMode;}
    if ($omitThreshold) {print " - Omit Threshold: ".$omitThreshold;}
    if ($sourceThreshold) {print " - Source Threshold: ".$sourceThreshold;}
    if ($eventThreshold) {print " - Event Threshold: ".$eventThreshold;}
    if ($targetThreshold) {print " - Target Threshold: ".$targetThreshold;}
    if ($sourceFanOutThreshold) {print " - Source Fan Out: ".$sourceFanOutThreshold;}
    if ($eventFanOutThreshold) {print " - Event Fan Out: ".$eventFanOutThreshold;}
    if ($propFileName) {print " - Property File: ".$propFileName;}
    print "\", fontsize=8]\n"; 
} elsif (!$gdf) {
    print "graph [label=\"AfterGlow ".$version."\", fontsize=8];\n";
}

# print "graph [bgcolor=black];\n";
# print "node [shape=ellipse, fillcolor=deepskyblue3, style=filled, fontsize=10, width=0.5, height=0.08, label=\"$source\"];\n";

my $options = "";

if (defined(@sourceSizeExp) || defined(@eventSizeExp) || defined(@targetSizeExp)) { 
    $options = ", fixedsize=true";
}

if ($url) {
    $options .= ", URL=\"$url\"";
}

# Default, global variables
if (!$gdf) {
    print "node [shape=ellipse, style=filled, penwidth=0, fontsize=10, width=$maxNodeSize, height=$maxNodeSize, fontcolor=\"$labelColor\", label=\"\" $options];\n";
    print "edge [len=$edgelen];\n";
}

# The line counter.
$lineCount = 0;

# Read each line from the file.
while (($lineCount < $skipLines + $maxLines) and $line = <STDIN>) {
   
    chomp ($line);       

    # Increment the line count.
    $lineCount += 1;
    
    # Verbose progress output.
    if ($verbose) {
       if ($lineCount < $skipLines) { $skippedLines = $lineCount; }
       else { $skippedLines = $skipLines; }
       $processedLines = $lineCount - $skipLines if $verbose;
       print STDERR "\rLines read so far: $lineCount. Skipped: $skippedLines. Processed: $processedLines";
    }

    # Are we still suppoed to skip lines?
    next if $lineCount < $skipLines;
    
    # Split the input into source, event and target.
    $csvline->parse($line);
    @fields = $csvline->fields();

    if ($twonodes) {
        $source = $fields[0];
        $target = $fields[1];
        $meta1 = $fields[2];
        $meta2 = $fields[3];
        print STDERR "====> Processing: $source -> $target\n" if $verbose;
    }
    else {
        $source = $fields[0];
        $event = $fields[1];
        $target = $fields[2];
        $meta1 = $fields[3];
        $meta2 = $fields[4];
        print STDERR "====> Processing: $source -> $event -> $target\n" if $verbose;
    };

    # Figure out the clustering

    # if any of the cluster regexes matches, make a new node with the cluster name
    if (@clusters) { 
        $type="source";
        $source=getCluster($source,@clusters); 
        $type="target";
        $target=getCluster($target,@clusters);
        $type="event";
        $event=getCluster($event,@clusters) unless ($twonodes);
    }
    if (@source_clusters) { 
        $type="source";
        $source=getCluster($source,@source_clusters);
    }
    if ((@event_clusters) && (!$twonodes) ) { 
        $type="event";
        $event=getCluster($event,@event_clusters); 
    }
    if (@target_clusters) { 
        $type="target";
        $target=getCluster($target,@target_clusters);
    }

    # we also have to change the fields array, not just the individual values
    # in order to make the colors work, they are using the fields array!
    if ($twonodes) {
        # Wow... UGLY. BUT: If you are using a -t option on a three-column input,
        # you might want to use the third column to steer some kind of property (size, etc.)
        # In order for that to work, we need to add this value back here ;)
        @fields=($source,$target,$fields[2],$meta1,$meta2); 
    } else {
        @fields=($source,$event,$target,$meta1,$meta2);
    }

    # End Clustering

    # Edges with invisible nodes are discarded all the way
    if (getColor("sourcetarget", @fields) eq $invisibleColor) { next; }
    if ($twonodes) {
        if ((getColor("source", @fields) eq $invisibleColor) 
        || (getColor("target", @fields) eq $invisibleColor)) { next; }

    } else {
        if ((getColor("source", @fields) eq $invisibleColor) 
        || (getColor("event",@fields) eq $invisibleColor)
        || (getColor("target", @fields) eq $invisibleColor)) { next; }
    }

    # Figure out the node names.
    $sourceName = &getSourceName($source, $event, $target, $splitSourceAndTargetNodes);
    $eventName = &getEventName($source, $event, $target, $splitSourceAndTargetNodes) unless ($twonodes);
    $targetName = &getTargetName($source, $event, $target, $splitSourceAndTargetNodes);

    # Figure out color for source node and store it. 
    # Known limitation: the last value this evaluates to is the one that will be used.
    # A nice thing would be nodes that have multiple colors.
    $sourceColorMap{$sourceName} = getColor("source", @fields);

    # count how many times a source shows up. This allows for filtering based on how many times
    # a node is used in the graph.
    $sourceCount{$sourceName} += 1;

    # keep track of the node's label
    $source=getLabel("source", @fields);
    # print STDERR "sourceLabel: $source / @fields\n";
    if ($source eq "__NULL_") {
    $sourceMap{$sourceName} = "";         
    } else {
    $sourceMap{$sourceName} = $source;
    }

    # keep track of fan out : a reference to the hash!
    # only evaluate if option is used!
    if ($sourceFanOutThreshold > 0) {
        my $temp = $sourceFanOut{$sourceName};
        my %foo = %$temp;

        if ($twonodes) {
        $foo{$targetName}=1;
        } else {
        $foo{$eventName}=1;
        }
        $sourceFanOut{$sourceName} = \%foo;
    }

    # calculate the size of the node
    if (defined(@sourceSizeExp)) { 
        # calculate the size of the node. Add to existing value to take care of 
        # source/target nodes and nodes showing up multiple times
        if ($sumSource) {
            $sourceNodeSize{$sourceName} += getSize("source",@fields);
        } else {
            $sourceNodeSize{$sourceName} = getSize("source",@fields);
        }
            if ($sourceNodeSize{$sourceName} > $maxActualSourceNodeSize) { $maxActualSourceNodeSize = $sourceNodeSize{$sourceName}; }
    }


    if (!$twonodes) {
        # repeat all the above for the event node
        $eventColorMap{$eventName} = getColor("event", @fields);
        $eventCount{$eventName} += 1;
        $event=getLabel("event", @fields);
        if ($event eq "__NULL_") {
        $eventMap{$eventName} = "";         
        } else {
        $eventMap{$eventName} = $event;
        }
        
            if ($eventFanOutThreshold > 0) {
            # fan out : a reference to the hash!
            $temp = $eventFanOut{$eventName};
            my %foo = %$temp;
            $foo{$targetName}=1;
            $eventFanOut{$eventName} = \%foo;
        }

        # calculate the size of the node. Add to existing value to take care of 
        # source/target nodes and nodes showing up multiple times
        if (defined(@eventSizeExp)) { 
                if ($sumEvent) {
                $eventNodeSize{$eventName} += getSize("event",@fields);
            } else {
                $eventNodeSize{$eventName} = getSize("event",@fields);
            }
                   if ($eventNodeSize{$eventName} > $maxActualEventNodeSize) { $maxActualEventNodeSize = $eventNodeSize{$eventName}; }
        }

    }
    
    # repeat all the above for the target node
    $targetColorMap{$targetName} = getColor("target", @fields);
    $targetCount{$targetName} += 1;
    $target=getLabel("target", @fields);
    if ($target eq "__NULL_") {
       $targetMap{$targetName} = "";         
    } else {
        $targetMap{$targetName} = $target;
    }
    if (defined(@targetSizeExp)) { 
        if ($sumTarget) {
            $targetNodeSize{$targetName} += getSize("target",@fields);
        } else {
            $targetNodeSize{$targetName} = getSize("target",@fields);
        }
        if ($targetNodeSize{$targetName} > $maxActualTargetNodeSize) { $maxActualTargetNodeSize = $targetNodeSize{$targetName}; }
    }

    # source / target nodes... Because the node is going to be a source and target, it is okay
    # to only keep track of the color for the source node.
    $sourcetargetColorMap{$sourceName} = getColor ("sourcetarget", @fields);

    # Edge Colors::
            
    # Add to maps. We need this is order to pick the proper
    # name for each node to add labels and other properties.
    if ($twonodes) {

        $sourceTargetLinkName = "$sourceName $targetName";
        $sourceTargetLinkMap{$sourceTargetLinkName} = $sourceTargetLinkName; 

        # Edge Color
    if (defined(@edgeColorExp)) {
        $edgeColor{$sourceTargetLinkName} = getColor("edge",@fields);
    }
    # Edge Size
    if (defined(@edgeSizeExp)) {
        $edgeSize{$sourceTargetLinkName} = getSize("edge",@fields);
    }


    } else {

        $sourceEventLinkName = "$sourceName $eventName";
        $sourceEventLinkMap{$sourceEventLinkName} = $sourceEventLinkName;

        # Edge Color
    if (defined(@edgeColorExp)) {
        $edgeColor{$sourceEventLinkName} = getColor("edge",@fields);
    }
    # Edge Size
    if (defined(@edgeSizeExp)) {
        $edgeSize{$sourceEventLinkName} = getSize("edge",@fields);
    }

        $eventTargetLinkName = "$eventName $targetName";
        $eventTargetLinkMap{$eventTargetLinkName} = $eventTargetLinkName;

        # Edge Color
    if (defined(@edgeColorExp)) {
        $edgeColor{$eventTargetLinkName} = getColor("edge",@fields);
    }
    # Edge Size
    if (defined(@edgeSizeExp)) {
        $edgeSize{$eventTargetLinkName} = getSize("edge",@fields);
    }

    }

}

# We are done with all the book kepping, output everything we learned

# First work on the edges (don't print, but remember)
my $edge_output = "";        # holds the data for edges to print later
if ($twonodes) {

    for my $sourceTargetLinkName (keys %sourceTargetLinkMap) {

    # TBD: Can we make this parsing safer?
    my ($sourceName, $targetName) = $sourceTargetLinkName =~ /("[^"]*") (.*)/;

    # do the fan out calculation
    my $fanout=1; # set to one to make the check further down true if the threshold 
                # is not set
    if ($sourceFanOutThreshold > 0) {
        my $temp = $sourceFanOut{$sourceName};
        $fanout = keys %$temp;
    }

    # either of the nodes needs a support of > $omitThreshold to be drawn
    # and the source-node needs a fan out > sourceFanOutThreshold
    if (($sourceCount{$sourceName} > $omitThreshold) 
        && ($sourceCount{$sourceName} > $sourceThreshold)
        && ($targetCount{$targetName} > $omitThreshold) 
        && ($targetCount{$targetName} > $targetThreshold)
        && ($fanout > $sourceFanOutThreshold) ) {

        # Color
        my $color = ();
        if (defined(@edgeColorExp)) {
            $color = $edgeColor{$sourceTargetLinkName};
        }

        # Size 
        my $size = 0;
        if (defined(@edgeSizeExp)) {
            $size = $edgeSize{$sourceTargetLinkName};
        }

        # print STDERR "size: $size / color: $color / gdf: $gdf\n";
        
        # Source -> target link. 

        if ($gdf) {
            if ($size == 0) { $size = 1; }
            $edge_output .= "$sourceName,$targetName,true,".rgb($color).",$size\n"; 
        } else {
            $edge_output .= "$sourceName -> $targetName"; 
            if ($size || $color) {
                $edge_output .= "[";
                if (defined($color)) { $edge_output .= "color=$color, style=$edgeStyle";}
                if (defined($color) && $size>0) { $edge_output .= ","; }
                if ($size>0) { $edge_output .= "penwidth=$size"; }
                $edge_output .= "]";
            }
            $edge_output .= "\n";
        }

        $printNode{$sourceName}=1;
        $printNode{$targetName}=1;

    } else {

        print STDERR "Omitting: $sourceName -> $targetName\n" if ($verbose);
        
    }

    }

} else {
    # not two-node mode!

    # we need to do the event target pair first do determine Problem Number 1 below
    for my $sourceEventLinkName (keys %sourceEventLinkMap) {
        
        # Source -> event link.
    my ($sourceName, $eventName) = $sourceEventLinkName =~ /("[^"]*") (.*)/;

    my $sourceSize = 1;
        if ($sourceFanOutThreshold > 0) {
        my $temp = $sourceFanOut{$sourceName};
        $sourceSize = keys %$temp;
    }
    my $eventSize = 1;
        if ($eventFanOutThreshold > 0) {
        my $temp = $eventFanOut{$eventName};
        $eventSize = keys %$temp;
    }
    
    #print STDERR "sourceFanOut: $sourceName: $fanout\n";

    if (($sourceCount{$sourceName} > $omitThreshold) 
        && ($sourceCount{$sourceName} > $sourceThreshold)
        && ($eventCount{$eventName} > $omitThreshold)
        && ($eventCount{$eventName} > $eventThreshold)
        && ($sourceSize > $sourceFanOutThreshold) 
        && ($eventSize > $eventFanOutThreshold) ) {

        # Color
        my $color = ();
        if (defined(@edgeColorExp)) {
            $color = $edgeColor{$sourceEventLinkName};
        }
    
        # Size
        my $size = 0;
        if (defined(@edgeSizeExp)) {
            $size = $edgeSize{$sourceEventLinkName};

            # print STDERR "size: $size / color: $color\n";
        }
        
        # Source -> Event link. 

        if ($gdf) {
            if ($size == 0) { $size = 1; }
            $edge_output .= "$sourceName,$eventName,true,".rgb($color).",$size\n"; 
        } else {
            $edge_output .= "$sourceName -> $eventName"; 
            if ($size || $color) {
                $edge_output .= " [";
                if (defined($color)) { $edge_output .= "color=$color,style=$edgeStyle";}
                if (defined($color) && $size>0) { $edge_output .= ","; }
                if ($size>0) { $edge_output .= "penwidth=$size"; }
                $edge_output .= "];";
            }
            $edge_output .= "\n";
        }

        $printNode{$sourceName}=1;
        $printNode{$eventName}=1;

    } else {

        print STDERR "Omitting: $sourceName -> $eventName\n" if ($verbose);

    }

    }

    for my $eventTargetLinkName (keys %eventTargetLinkMap) {

    # Event -> target link.
    my ($eventName, $targetName) = $eventTargetLinkName =~ /("[^"]*") (.*)/;

    if (!$printNode{$eventName}) {
        next;
    }

    my $fanout = 1;
    if ($eventFanOutThreshold > 0) {
        my $temp = $eventFanOut{$eventName};
        $fanout = keys %$temp;
    }
    
    if ( ($eventCount{$eventName} > $omitThreshold) 
        && ($eventCount{$eventName} > $eventThreshold)
        && ($targetCount{$targetName} > $omitThreshold)
        && ($targetCount{$targetName} > $targetThreshold)
        && ($fanout > $eventFanOutThreshold) ) {
        # print STDERR "targetFanOut: $targetName: $fanout\n";

        # Color
        my $color = ();
        if (defined(@edgeColorExp)) {
            $color = $edgeColor{$eventTargetLinkName};
        }

        # Size
        my $size = 0;
        if (defined(@edgeSizeExp)) {
            $size = $edgeSize{$eventTargetLinkName};
        }

        # print STDERR "size: $size / color: $color\n";
        
        # Event -> Target link. 

        if ($gdf) {
            if ($size == 0) { $size = 1; }
            $edge_output .= "$eventName,$targetName,true,".rgb($color).",$size\n"; 
        } else {
            $edge_output .= "$eventName -> $targetName"; 
            if ($size || $color) {
                $edge_output .= " [";
                if (defined($color)) { $edge_output .= "color=$color,style=$edgeStyle";}
                if (defined($color) && $size>0) { $edge_output .= ","; }
                if ($size>0) { $edge_output .= "penwidth=$size"; }
                $edge_output .= "];";
            }
            $edge_output .= "\n";
        }

        $printNode{$eventName}=1;
        $printNode{$targetName}=1;

    } else {

        # Probelm Number 1: if the eventNode or the targetNode is not displayed for 
        # some reason, we have to check that the sourceNode that belongs to these guys 
        # still has neighbors! Otherwise it has to be eliminated as well!
        # This scenario is taken care of in the next section...
        
        print STDERR "Omitting: $eventName -> $targetName\n" if ($verbose);

    }

    }

}
  
# Done with the edges, now come the nodes
if ($gdf) { 
    print "nodedef>name VARCHAR,label VARCHAR,width DOUBLE,height DOUBLE,color VARCHAR\n";
}

# Write properties for the source nodes.
foreach $sourceName (keys %sourceMap) {

    my $fanout=1;
    if ($sourceFanOutThreshold > 0) {
        my $temp = $sourceFanOut{$sourceName};
        $fanout = keys %$temp;
    }
    
    if (($sourceCount{$sourceName} <= $omitThreshold) 
        || ($sourceCount{$sourceName} <= $sourceThreshold)
        || ($fanout <= $sourceFanOutThreshold) 
        || (!$printNode{$sourceName}) )  {
        
        $sourceMap{$sourceName}=();     # set to null so it could still 
                                        # be written as the target node
        print STDERR "Omitting Node: $sourceName \n" if ($verbose);
        next;
    }

    # Assign differnet color to a node which is a source and target at the same time?
    if ($targetMap{$sourceName}) {
        if (defined(@sourcetargetColorExp)) {
            $sourceColor = $sourcetargetColorMap{$sourceName};
        } else {
            # print the node already here instead of in the target section
            if (defined(@sourceColorExp)) {
                $sourceColor = $sourceColorMap{$sourceName};
            } else {
                $sourceColor = $targetColorMap{$sourceName};
            }
        }
    } else {
        $sourceColor = $sourceColorMap{$sourceName};
    }

    $source = $sourceMap{$sourceName};

    if (!$nodeLabels) { $source=""; } 
    if (!$sourceLabel) { $source=""; } 

    if (!$sourceColor) { 
        print STDERR "Color Not Assigned for: $source\n";
        $sourceColor="white";
    }

    if ($printSourceNodes) {
        print STDERR $source."\n";
    }

    # Prepare the node properties
    print $sourceName;
    if ($nodeCount) { $source .= " : ".$sourceCount{$sourceName}; }

    if ($gdf) {

        print ",\"$source\"";       # this is the label

        # size of node
        my $size=1;
        if (defined(@sourceSizeExp)) { 
            $size = sprintf ("%.2f",($maxNodeSize / $maxActualSourceNodeSize) * $sourceNodeSize{$sourceName});
        }
        print ",$size";
        print ",$size";
        print ",".rgb($sourceColor)."\n";

    } else {

        if ($xlabels) { $ll = "xlabel=\"$source\""; } else { $ll = "label=\"$source\""; }
        my $out = " [fillcolor=$sourceColor, $ll";

        # size of node
        if (defined(@sourceSizeExp)) { 
            #print STDERR "MaxActualSize: $maxActualSourceNodeSize maxNodeSize: $maxNodeSize currentSize: $sourceNodeSize{$sourceName}\n";
            my $size=0;
            $size = sprintf ("%.2f",($maxNodeSize / $maxActualSourceNodeSize) * $sourceNodeSize{$sourceName});
            $out .= ",width=\"$size\"";
            $out .= ",height=\"$size\"";
        }

        if ($shapeSource ne "ellipse") {
            $out .= ",shape=$shapeSource";
        }
        
        $out .= "]\n";
        print $out;

    }


}

# Write properties for the event nodes.
unless ($twonodes) {

    foreach $eventName (keys %eventMap) {

        # prevent overwriting an already defined node.
        if ($sourceMap{$eventName}) { next; }

        my $size=1;
        if ($eventFanOutThreshold > 0) {
            my $temp = $eventFanOut{$eventName};
            $size = keys %$temp;
        }

        if (($eventCount{$eventName} <= $omitThreshold) 
            || ($eventCount{$eventName} <= $eventThreshold)
            || ($size <= $eventFanOutThreshold)
            || (!$printNode{$eventName}) )  {

            $eventMap{$eventName}=();     # set to null so it could still 
                                          # be written as the target node
            print STDERR "Omitting Node: $eventName \n" if ($verbose);
            next;

        }

        $eventColor = $eventColorMap{$eventName};

        if ((!$nodeLabels) || (!$eventLabel)) { 
            $event=""; 
        } else { 
            $event = $eventMap{$eventName}; 
        }

        if (!$eventColor) { 
            print STDERR "Color Not Assigned for: $event\n";
            $eventColor="cyan";
        }

        # Prepare the node properties
        print $eventName;
        if ($nodeCount) { $event .= " : ".$eventCount{$eventName}; }

        if ($gdf) {

            print ",\"$event\"";       # this is the label

            # size of node
            my $size=1;
            if (defined(@seventSizeExp)) { 
                $size = sprintf ("%.2f",($maxNodeSize / $maxActualEventNodeSize) * $eventNodeSize{$eventName});
            }
            print ",$size";
            print ",$size";
            print ",".rgb($eventColor)."\n";

        } else {

            if ($xlabels) { $ll = "xlabel=\"$event\""; } else { $ll = "label=\"$event\""; }
            my $out = " [shape=box, fillcolor=$eventColor, $ll";

            # size of node
            if (defined(@eventSizeExp)) { 
                my $size=0;
                $size = sprintf ("%.2f",($maxNodeSize / $maxActualEventNodeSize) * $eventNodeSize{$eventName});
                $out .= ",width=\"$size\"";
                $out .= ",height=\"$size\"";
            }

            # Node Shape
                if ($shapeEvent ne "ellipse") {
                $out .= ",shape=$shapeEvent";
            }
                
            $out .= "]\n";
            print $out;
        }

    }

}

# Write properties for the target nodes.
foreach $targetName (keys %targetMap) {

    # prevent overwriting an already defined node.
    if ($sourceMap{$targetName}) { next; }
    if ($eventMap{$targetName}) { next; }

    if ( ($targetCount{$targetName} <= $omitThreshold) 
            || ($targetCount{$targetName} <= $targetThreshold)
            || (!$printNode{$targetName}) )  {

        print STDERR "Omitting Node: $targetName \n" if ($verbose);
        next;
    }

    # The source/target coloring is already done in the source node part.
    $targetColor = $targetColorMap{$targetName};

    $target = $targetMap{$targetName};

    if (!$nodeLabels) { $target=""; } 
    if (!$targetLabel) { $target=""; } 
    if (!$targetColor) { 
        print STDERR "Color Not Assigned for: $target\n";
        $targetColor="red";
    }

    print $targetName;
    if ($nodeCount) { $target .= " : ".$targetCount{$targetName}; }

    if ($gdf) {

        print ",\"$target\"";       # this is the label

        # size of node
        my $size=1;
        if (defined(@targetSizeExp)) { 
            $size = sprintf ("%.2f",($maxNodeSize / $maxActualTargetNodeSize) * $targetNodeSize{$targetName});
        }
        print ",$size";
        print ",$size";
        print ",".rgb($sourceColor)."\n";

    } else {

        if ($xlabels) { $ll = "xlabel=\"$target\""; } else { $ll = "label=\"$target\""; }
        my $out = " [fillcolor=$targetColor, $ll";

        # size of node
        if (defined(@targetSizeExp)) { 
            # print STDERR "MaxActualSize: $maxActualTargetNodeSize maxNodeSize: $maxNodeSize currentSize: $targetNodeSize{$targetName} targetName: $targetName\n";
            my $size=0;
            $size = sprintf ("%.2f",($maxNodeSize / $maxActualTargetNodeSize) * $targetNodeSize{$targetName});
            $out .= ",width=\"$size\"";
            $out .= ",height=\"$size\"";
        }

        # Node Shape
        if ($shapeTarget ne "ellipse") {
            $out .= ",shape=$shapeTarget";
        }
        
        $out .= "]\n";
        print $out;

    }
    
}

# now that the nodes have been printed, print the edges.
if ($gdf) {print "edgedef>node1 VARCHAR,node2 VARCHAR,directed BOOLEAN,color VARCHAR,weight DOUBLE\n";}
print $edge_output;

# Write dot footer.
if (!$gdf) {
    print "}\n";
}

# Debug output.
print STDERR "\n\nAll over, buster.\n" if $verbose;

#
#
# And this is the end of all things.
#
#

# ------------------------------------------------------------
# Translating color to RGB for GDF format
# ------------------------------------------------------------
sub rgb {
    my ($col) = @_;
    my $rgb;
    if (!$col) { return $defaultColor; }
    $ret = $color_to_rgb_map{$col};
    if (!$ret) { print STDERR "ERROR: no RGB value found for color: $col\n";}
    return "'$ret'"
}

# ------------------------------------------------------------
# Color-Properties Subroutines.
# ------------------------------------------------------------

# function: subnet(value,network/mask)
# return:   0 or 1 depending on whether value is in the network 
#           with the given mask
# example:  subnet($fields[0],0.0.0.0/7)
# Note:     I am sure you can make this more efficient (instead 
#         of converting both IPs and then masking them.
#         Well, thinking about it while running, this is needed.
sub subnet {
    my ($value,$value2) = @_;

    my @temp = split(/\./,$value);
    # return if not an IP address
    return(0) if (scalar(@temp) != 4);    # very simplistic test!

    my $ip=unpack("N",pack("C4",@temp));

    my ($network,$mask) = $value2 =~ /([^\/]+)\/(.*)/;
    $network=unpack("N",pack("C4",split(/\./,$network)));

        $mask = (((1 << $mask) - 1) << (32 - $mask));
    $newNet = join(".",unpack("C4",pack("N",$ip & $mask)));
    $newNetwork = join(".",unpack("C4",pack("N",$network & $mask)));

    # return ($network == $newNet);
    if ($newNetwork eq $newNet) {
        # print STDERR "match: $value newnetwork: $newNetwork newNet: $newNet\n";
        return 1;
    } else {
        # print STDERR "no match: $value newNetwork: $newNetwork network: $network newNet: $newNet\n";
        return 0;
    }
}

# function: any_regex("match_and_return_regex")
# return:   0 or 1 depending on whether the regex matches on any of
#         the columns
# example:  TBD
sub any_regex {
    ($value) = @_;
    #print STDERR "any_regex(): $value\n";
    foreach my $field (@fields) {
        if ($field =~ /$value/) {
            return 1;
        }
    }
    return 0;
}

# function: field()
# return:   Type-relative (source, event, target). 
#      
# example:  "red" if (field() eq "foo");
sub field {

    if ($type eq "sourcetarget") { return $fields[0];}
    if ($type eq "source") { return $fields[0];}
    if (($type eq "event") || ($twonodes)) { return $fields[1];}
    if (($type eq "target") && (!$twonodes)) { return $fields[2];}

}

# ram: 06/28/06 This is really the same as match() without the global field, but that is set
#               anyways, so killing it!
# function: regex("match_and_return_regex")
# return:   
#         Type-relative (source, event, target). Only returns if that column 
#         matches.
#      
# example:  color="cornflowerblue" if (regex("Internal"));
# sub regex {
# ($value) = @_;
# #print STDERR "type: $type / value: $value\n";
# if ($type eq "source") { return ($fields[0] =~ /$value/)[0];}
# if (($type eq "event") || ($twonodes)) { #print STDERR "foo: $fields[1]\n";
# return ($fields[1] =~ /$value/)[0];}
# if (($type eq "target") && (!$twonodes)) { return ($fields[2] =~ /$value/)[0];}
# }

sub match {
    ($regex) = @_;
    return $globalField =~ /$regex/;
}

# function: regex_replace("replace_regex")
# return:   Use a regular expression to replace the input string. The match is 
#         returned
#         Type-relative (source, event, target). Only returns if that column 
#         matches.
# example:  cluster.source=regex_replace("(\\d\+\\.\\d+)")."/16" \
#           if (!match("^(212\.254\.110|195\.141\.69)")) 
#        if one of the two ranges match(), then return the first two octets of 
#        the source IP and add the "/16" string.
sub regex_replace {
    ($regex) = @_;
    #print STDERR "globalField: $globalField / regex: $regex \n";

    return ($globalField =~ /$regex/)[0]; 
}

# function: get_severity(severity, [steps])
# return:   A hex color string based on the severity of the input and the number
#           of steps, which indicate highest severity
# example:  color.source=get_severity($fields[2])
sub interpolate {
    ($pBegin, $pEnd, $pStep, $pMax) = @_;

    if ($pBegin < $pEnd) {
      return (($pEnd - $pBegin) * ($pStep / $pMax)) + $pBegin;
    } else {
      return (($pBegin - $pEnd) * (1 - ($pStep / $pMax))) + $pEnd;
    }

}

sub get_severity {
    ($value, $steps) = @_;

    if (!$steps) { $steps = 10; }  # if number of steps is not defined, make it 10
    # round the value
    $x = int($value + .5 * ($value <=> 0));
    $start = 0x60BB22;
    $end = 0xCC0000;

    if ($x >= $steps) {
        $x = $steps;
    }

    $theR0 = ($start & 0xff0000) >> 16;
    $theG0 = ($start & 0x00ff00) >> 8;
    $theB0 = ($start & 0x0000ff) >> 0;

    $theR1 = ($end & 0xff0000) >> 16;
    $theG1 = ($end & 0x00ff00) >> 8;
    $theB1 = ($end & 0x0000ff) >> 0;
    $theR = interpolate($theR0, $theR1, $x, $steps);
    $theG = interpolate($theG0, $theG1, $x, $steps);
    $theB = interpolate($theB0, $theB1, $x, $steps);

    $theVal = ((($theR << 8) | $theG) << 8) | $theB;
    return sprintf("#%06X", $theVal);

}



# function: notreg("return_regex","match_regex")
# return:   Execute the return_regex on the field, if match_regex does NOT match. 
#         Type-relative (source, event, target). Only returns if that column 
#         matches.
# example:  cluster.source=notreg("(\\d\+\\.\\d+)","^(212\.254\.110|195\.141\.69)")
#        if NOT one of the two ranges, then return the first two octets of the IP
#        restrict to only source nodes!
#sub notreg {
#($output,$match) = @_;
#if (!match($match)) { return ($globalField=~/$output/)[0]; }
#}

# ------------------------------------------------------------
# Subroutines.
# ------------------------------------------------------------

# Computes clusters
sub getCluster {
 
    my ($field,@clusters) = @_;
    my $return;

    for my $cluster (@clusters) {
        #print STDERR "getCluster() field: $field / cluster: $cluster\n";    

        # setting the globalField for the function!
        $globalField=$field;

        if ($return = eval ($cluster)) { last; }

    }

    if ($return) {$field=$return;} 
    #print STDERR "return: $field\n";    
    return $field;

}

# Computes the name to use for a source node.
sub getSourceName {
    
    # Get the arguments.
    ($source, $event, $target) = @_;

    # Return value depends on whether or not to split nodes.
    return "\"S:$source\"" if $splitSourceAndTargetNodes;
    return "\"$source\"";
}

# Computes the name to use for a source node.
sub getEventName {
    
    # Get the arguments.
    ($source, $event, $target) = @_;

    return "\"$source $event\"" if $eventNodeSplitMode == 1;
    return "\"$event $target\"" if $eventNodeSplitMode == 2;
    return "\"$source $event $target\"" if $eventNodeSplitMode == 3;
    return "\"$event\"";
}

# Computes the name to use for a source node.
sub getTargetName {
    
    # Get the arguments.
    ($source, $event, $target) = @_;

    # Return value depends on whether or not to split nodes.
    return "\"T:$target\"" if $splitSourceAndTargetNodes;
    return "\"$target\"";
}

# Return the color for this node

# Optimization FROM: 
# %Time ExclSec CumulS #Calls sec/call Csec/c  Name
#  75.5   10.78 15.242   6000   0.0018 0.0025  main::getColor
#  31.0   4.434  4.434 192000   0.0000 0.0000  main::subnet
# TO:
#  76.3   0.636  0.731   6000   0.0001 0.0001  main::getColor
#  10.5   0.088  0.088   1920   0.0000 0.0000  main::subnet
# By using a cache!
sub getColor {

    print STDERR "getColor()" if $DEBUG;
    
    # Get the arguments
    # type element of ["source"|"target"|"event"]
    ($type, @fields) = @_;

    # build a cache so we don't have to go through it all
    my $index;
    if ($twonodes) {
        $index = $fields[0].$fields[1].$type; 
    } else {
        $index = $fields[0].$fields[1].$fields[2].$type;
    }

    # cache hit?
    if (defined($cache{$index})) { 
        print STDERR " cache hit: $cache{$index}\n" if $DEBUG;
        return $cache{$index}; 
    }

    $variableColExp = $type."ColorExp";
    my $color=();

    # setting the globalField for the functions!
    if (($type eq "source") || ($type eq "sourcetarget")) {$globalField=$fields[0];}
    if ($twonodes) {
        if ($type eq "target") {$globalField=$fields[1];}
    } else {
    if ($type eq "event") {$globalField=$fields[1];}
         if ($type eq "target") {$globalField=$fields[2];}
    }

    print STDERR " | value: $globalField" if $DEBUG;
    print STDERR " | type: $type" if $DEBUG;

    if ($notCatchAllColor{$type.$globalField}) {
        # print STDERR "$type :: $globalField\n";
        return $notCatchAllColor{$type.$globalField};
    }

    for my $var (@$variableColExp) {
        print STDERR " | eval: $var" if $DEBUG;
        print STDERR " | field(): ".field() if $DEBUG;
    
        if ($var =~ /^#[\da-fA-F]{6,8}$/) { 
            $color = $var;
            last;
        } elsif ($color = eval($var)) {
            # check whether the assignment happened in a "catch-all" condition, which can
            # be identified by not having a "if" in the statement.
            # if ($type eq "target") {print STDERR "eval: $var :: $fields[1]\n";}
            #if ($var =~ /if/) {$notCatchAllColor{$type.$globalField}=$color;}
            last;
        }
    }

    print STDERR " | color: $color" if $DEBUG;

    # if the entry in the log is not a color name, index ourselves
    if ($color =~ /\#[\da-fA-F]{6,8}/) {
        $color="\"$color\"";
    }
    elsif ((!grep(/$color/,@colors))  || (!defined($color))) {

        # did we already index this color?
        if (exists($colorIndex{$color})) {
            $color=$colorIndex{$color};
         } else {    

            # Only scream if the color was actually set.
            if ($color) {print STDERR "Not a color: $color\n";}

            $colorIndex{$color}=$colors[$colorIndexCount];    
            $color=$colors[$colorIndexCount];
            $colorIndexCount ++;
        }
    }

    # add to cache
    $cache{$index} = $color;

    print STDERR "\n" if $DEBUG;

    # Error check, printing it is not really useful.
    # if (!$color) { print STDERR "ERROR: No color assigned\n"; }
    return $color;

}

sub getSize {
    
    # Get the arguments
    # type element of ["source"|"target"|"event"]
    ($type, @fields) = @_;

    # build a cache so we don't have to go through it all
    #my $index;
    #if ($twonodes) {
    #$index = $fields[0].$fields[1].$type; 
    #} else {
    #$index = $fields[0].$fields[1].$fields[2].$type;
    #}

    # cache hit?
    #if (defined($cache{$index})) { return $cache{$index}; }

    # setting the globalField for the functions! [sourcetarget is no really needed
    # but it does not hurt]
    if (($type eq "source") || ($type eq "sourcetarget")) {$globalField=$fields[0];}
    if ($twonodes) {
        if ($type eq "target") {$globalField=$fields[1];}
    } else {
    if ($type eq "event") {$globalField=$fields[1];}
         if ($type eq "target") {$globalField=$fields[2];}
    }

    $variableSizeExp = $type."SizeExp";
    my $size=0;

    if ($notCatchAllSize{$type.$globalField}) {
        # print STDERR "$type :: $globalField\n";
        return $notCatchAllSize{$type.$globalField};
    }

    for my $var (@$variableSizeExp) {
        if ($size = eval($var)) { 
            # check whether the assignment happened in a "catch-all" condition, which can
            # be identified by not having a "if" in the statement.
            # if ($type eq "target") {print STDERR "eval: $var :: $fields[1]\n";}
            if ($var =~ /if/) {$notCatchAllSize{$type.$globalField}=$size;}
            last; 
        }
    }

    # for undefined edge sizes:
    if ((!$size) && ($type eq "edge")) {$size = $defaultEdgeSize;}
    
    # print STDERR "getSize: $size \n";

    # add to cache
    #$cache{$index} = $color;

    return $size;

}

sub getLabel {
    
    # Get the arguments
    # type element of ["source"|"target"|"event"]
    ($type, @fields) = @_;

    # build a cache so we don't have to go through it all
    #my $index;
    #if ($twonodes) {
    #$index = $fields[0].$fields[1].$type; 
    #} else {
    #$index = $fields[0].$fields[1].$fields[2].$type;
    #}

    # cache hit?
    #if (defined($cache{$index})) { return $cache{$index}; }

    # setting the globalField for the functions! [sourcetarget is no really needed
    # but it does not hurt]
    if (($type eq "source") || ($type eq "sourcetarget")) {$globalField=$fields[0];}
    if ($twonodes) {
        if ($type eq "target") {$globalField=$fields[1];}
    } else {
    if ($type eq "event") {$globalField=$fields[1];}
         if ($type eq "target") {$globalField=$fields[2];}
    }

    $variableLabelExp = $type."LabelExp";
    # print STDERR "$type :: $variableLabelExp\n";

    my $label=();

    if ($notCatchAllLabel{$type.$globalField}) {
        # print STDERR "$type :: $globalField\n";
        return $notCatchAllLabel{$type.$globalField};
    }

    for my $var (@$variableLabelExp) {
        #print STDERR "var: $var\n";
        if (($var eq "0") || ($var eq "")) {
            # no labels (Yes, it's __NULL_)
            $label="__NULL_";
            last;
        }
        if ($label = eval($var)) { 
            # check whether the assignment happened in a "catch-all" condition, which can
            # be identified by not having a "if" in the statement.
            # if ($type eq "target") {print STDERR "eval: $var :: $fields[1]\n";}
            if ($var =~ /if/) {$notCatchAllLabel{$type.$globalField}=$label;}
            last; 
        }
    }

    if (!defined($label)) {
        $label=$globalField;
    }

    #print STDERR "getLabel: $label \n";

    # add to cache
    #$cache{$index} = $color;

    return $label;

}

# Process property file
sub propertyfile() {

    if (!$propFileName) {
        print STDERR "No property file specified, using default settings.\n";
        return;
    }
    
    open PROPFILE, "< $propFileName" or die "Cannot open $propFileName: $!";

    my $line = 0;

    print STDERR "----------- Property File:\n" if ($verbose);

    while ($ln = <PROPFILE>) {


        $line++;

        chomp $ln;
        next if ($ln =~ /^\s*#/); # ignore comments
        next if ($ln =~ /^\s*$/); # ignore empty lines
        $ln =~ s/[^"]#.*$//;    # Remove line comments in the properties file.
        @nv = split /\s*=/,$ln,2;
        $value = $nv[1];
        $value =~ s/^\s*=?\s*//;
        $value =~ s/\s*$//;
        $value =~ s/;$//;
        $value =~ s/^"(.*)"$/\1/;
        $name = $nv[0];
        $name =~ s/^\s*//;
        $name =~ s/\s*$//;

        # print STDERR "$name=$value\n"; ### DEBUG ###

        if ($name eq "gdf") {
            $gdf = 1;
        }
        elsif ($name eq "xlabels") {
            $xlabels = 1;
        }
        elsif ($name eq "color") {
            # generic coloring
            push (@sourceColorExp,$value);
            push (@targetColorExp,$value);
            push (@eventColorExp,$value);
            push (@sourcetargetColorExp,$value);
        } 
        elsif ($name eq "color.source") {
            push (@sourceColorExp,$value);
        } 
        elsif ($name eq "color.target") {
            push (@targetColorExp,$value);
        } 
        elsif ($name eq "color.event") {
            push (@eventColorExp,$value);
        }
        elsif ($name eq "color.edge") {
            push (@edgeColorExp,$value);
        }
        elsif ($name eq "color.sourcetarget") {
            push (@sourcetargetColorExp,$value);
            }
        elsif ($name eq "size") {
            push (@sourceSizeExp,$value);
            push (@targetSizeExp,$value);
            push (@eventSizeExp,$value);
            }
        elsif ($name eq "size.source") {
            push (@sourceSizeExp,$value);
            }
        elsif ($name eq "size.target") {
            push (@targetSizeExp,$value);
            }
        elsif ($name eq "size.event") {
            push (@eventSizeExp,$value);
            }
        elsif ($name eq "size.edge") {
            push (@edgeSizeExp,$value);
            }
        elsif ($name eq "threshold") {
            $omitThreshold = $value;
            $omitThreshold =~ s/.*?(\d*).*/\1/;
            }
        elsif ($name eq "threshold.source") {
            $sourceThreshold = $value;
            $sourceThreshold =~ s/.*?(\d*).*/\1/;
            }
        elsif ($name eq "threshold.event") {
            $eventThreshold = $value;
            $eventThreshold =~ s/.*?(\d*).*/\1/;
            }
        elsif ($name eq "threshold.target") {
            $targetThreshold = $value;
            $targetThreshold =~ s/.*?(\d*).*/\1/;
            }
        elsif ($name eq "shape.source") {
            if ($value !~ /^(box|polygon|circle|ellipse|invtriangle|octagon|pentagon|diamond|point|triangle|plaintext|Mrecord);?$/) {
                print STDERR "Property File Error, unrecognized value for shape.source: $value, line $line\n";
            } else {
                $shapeSource=$value;
                print STDERR "Source Shape: $shapeSource\n" if ($verbose);
            }
        }
        elsif ($name eq "shape.target") {
            if ($value !~ /^(box|polygon|circle|ellipse|invtriangle|octagon|pentagon|diamond|point|triangle|plaintext|Mrecord);?$/) {
                print STDERR "Property File Error, unrecognized value for shape.target: $value, line $line\n";
            } else {
                $shapeTarget=$value;
                print STDERR "Target Shape: $shapeTarget\n" if ($verbose);
            }
        }
        elsif ($name eq "shape.event") {
            if ($value !~ /^(box|polygon|circle|ellipse|invtriangle|octagon|pentagon|diamond|point|triangle|plaintext|Mrecord);?$/) {
                print STDERR "Property File Error, unrecognized value for shape.event: $value, line $line\n";
            } else {
                $shapeEvent=$value;
                print STDERR "Source Shape: $shapeEvent\n" if ($verbose);
            }
        }
        elsif ($name eq "sum.source") {
            if ($value !~ /^[01];?$/) {
                print STDERR "Property File Error, unrecognized value for sum.source: $value, line $line\n";
            } else {
                $sumSource=$value;
            }
        }
        elsif ($name eq "sum.target") {
            if ($value !~ /^[01]$/) {
                print STDERR "Property File Error, unrecognized value for sum.target: $value, line $line\n";
            } else {
                $sumTarget=$value;
            }
        }
        elsif ($name eq "sum.event") {
            if ($value !~ /^[01];?$/) {
                print STDERR "Property File Error, unrecognized value for sum.event: $value, line $line\n";
            } else {
                $sumEvent=$value;
            }
        }
        elsif ($name eq "label") {
            push (@sourceLabelExp,$value);
            push (@eventLabelExp,$value);
            push (@targetLabelExp,$value);
        }
        elsif ($name eq "label.source") {
            push (@sourceLabelExp,$value);
            #print STDERR "val: $value\n";
        }
        elsif ($name eq "label.target") {
            push (@targetLabelExp,$value);
        }
        elsif ($name eq "label.event") {
            push (@eventLabelExp,$value);
        }
        elsif ($name eq "url") {
            $url = $value;
        }
        elsif ($name =~ /^cluster/) {
            # print STDERR "cluster: $cluster_name $regex\n";
            if ($name eq "cluster") {
                push (@clusters,$value);
            } elsif ($name eq "cluster.source") {
                push (@source_clusters,$value);
            } elsif ($name eq "cluster.event") {
                push (@event_clusters,$value);
            } elsif ($name eq "cluster.target") {
                push (@target_clusters,$value);
            } else {
                print STDERR "Property File Error, unrecongnized name for cluster: $name, line $line\n";
            }
        }
        elsif (lc($name) eq "maxnodesize") {
            $maxNodeSize = $value;
            $maxNodeSize =~ s/.*?(\d*).*/\1/;
        }
        elsif ($name eq "variable") {
            eval $value;
        }
        elsif ($name eq "exit") {
            last;
        }
        else
        {
            print STDERR "Property File Error, unrecongnized entry: $name, line $line\n";
        }

    }
    
    print STDERR "----------- Done Reading Properties\n" if ($verbose);
    print STDERR "\n" if ($verbose);

    close(PROPFILE);

}

# Command line options processing.
sub init() {
    my %opt;
    use Getopt::Std;
    getopts("adknhtvsqri:w:p:l:b:e:c:o:f:g:m:x:", \%opt ) or usage();

    # Help?
    usage() if $opt{h};
    
    # Verbose?
    $verbose = 1 if $opt{v};

    # Number of lines to skip?
    $skipLines = $opt{b} if $opt{b};

    # Maximum number of lines to read?
    $maxLines = $opt{l} if $opt{l};

    # Two node mode (skip objects)?
    $twonodes = $opt{t} if $opt{t};

    # Split source and target nodes?
    $splitSourceAndTargetNodes = 1 if $opt{s};

    # Split mode for event nodes?
    $eventNodeSplitMode = $opt{p} if $opt{p};

    # Print node labels?
    $nodeLabels = 0 if $opt{n};

    # Edge Length
    $edgelen = $opt{e} if $opt{e};

    # Label Color
    $labelColor = $opt{x} if $opt{x};

    # Configuration file
    $propFileName= $opt{c} if ($opt{c});

    # Omit single nodes?
    $omitThreshold = $opt{o} if $opt{o};

    # Source FanOut Threshold
    $sourceFanOutThreshold = $opt{f} if $opt{f};

    # Event FanOut Threshold
    $eventFanOutThreshold = $opt{g} if $opt{g};

    # Print node count?
    $nodeCount = 1 if $opt{d};

    # Ouput configuration?
    $label = 1;        # set by default
    $label = 0 if $opt{a};

    # print source nodes?
    $printSourceNodes = 0;
    $printSourceNodes  = 1 if $opt{r};

    # Maximum node size
    $maxNodeSize = $opt{m} if $opt{m};

    # GDF output mode
    $gdf = 1 if $opt{k};

    if ($opt{q}) {
        open (STDOUT, ">/dev/null") or die ("Quiet mode did not work! Could not redirect STDOUT to /dev/null");
        open (STDERR, ">/dev/null") or die ("Quiet mode did not work! Could not redirect STDERR to /dev/null");
    }
    
    if ($opt{w}) {
        open (STDOUT, ">$opt{w}") or die ("Could not redirect STDERR to $opt{w}");
    }

    if ($opt{i}) {
        open (STDIN, "<$opt{i}") or die ("Could not redirect STDERR to $opt{i}");
    }

}

# Message about this program and how to use it.
sub usage() {

    print STDERR << "EOF";

Afterglow $version ---------------------------------------------------------------
    
A program to visualize network activitiy data using graphs.
Uses the dot graph layout program fromt the Graphviz suite.
Input data is expected to be in this simple CSV-style format:
    
    [subject],  [predicate], [object]
    10.10.10.10, ACCEPT,     216.239.37.99

Usage:   afterglow.pl [-adhnstv] [-b lines] [-c conffile] [-e length] [-f threshold ] [-g threshold] [-l lines] [-o threshold] [-p mode] [-x color] [-m maxsize]

-a           : turn off labelelling of the output graph with the configuration used
-b lines     : number of lines to skip (e.g., 1 for header line)
-c conffile  : color config file
-d           : print node count
-e length    : edge length
-f threshold : source fan out threshold
-g threshold : event fan out threshold (only in three node mode)
-h           : this (help) message
-i file      : read from input file, instead of from STDIN
-k           : output in GDF format instead of DOT
-l lines     : the maximum number of lines to read
-m           : the maximum size for a node
-n           : don't print node labels
-o threshold : omit threshold (minimum count for nodes to be displayed) 
           Non-connected nodes will be filtered too.
-p mode      : split mode for predicate nodes where mode is
                0 = only one unique predicate node (default)
                1 = one predicate node per unique subject node.
                2 = one predicate node per unique target node.
                3 = one predicate node per unique source/target node.
-q           : suppress all output. Attention! You should use -w to write output to a file!
-r           : print source node names
-s           : split subject and object nodes
-t           : two node mode (skip over objects)
-v           : verbose output
-w file      : write output to a file instead of STDOUT
-x           : text label color

Example: cat somedata.csv | afterglow.pl -v | dot -Tgif -o somedata.gif

The dot exectutable from the Graphviz suite can be obtained
from the AT&T research website: http://www.graphviz.org

EOF
    exit;
}


set storage Quickstep
env unset exportLimit
$my_process = vertices('f0f914ed76209d8b4bd41e44feab807d')
$my_lineage = $base.getLineage($my_process, 1, 'b')
$my_edges = $my_lineage.getEdge(datetime = '2/22/2022 7:07:25 AM')
$my_vertices = $my_edges.getEdgeEndpoints()
$my_graph = $my_edges + $my_vertices
export > /spade-data2/Jigsaw/benign/f0f914ed76209d8b4bd41e44feab807d/2022-02-22-07-07-25.dot
dump all $my_graph
$my_edges = $my_lineage.getEdge(datetime = '2/22/2022 7:07:28 AM')
$my_vertices = $my_edges.getEdgeEndpoints()
$my_graph = $my_edges + $my_vertices
export > /spade-data2/Jigsaw/benign/f0f914ed76209d8b4bd41e44feab807d/2022-02-22-07-07-28.dot
dump all $my_graph
$my_edges = $my_lineage.getEdge(datetime = '2/22/2022 7:07:26 AM')
$my_vertices = $my_edges.getEdgeEndpoints()
$my_graph = $my_edges + $my_vertices
export > /spade-data2/Jigsaw/benign/f0f914ed76209d8b4bd41e44feab807d/2022-02-22-07-07-26.dot
dump all $my_graph
$my_process = vertices('47d49ac2d3c5bb33137106f9c3b91e35')
$my_lineage = $base.getLineage($my_process, 1, 'b')
$my_edges = $my_lineage.getEdge(datetime = '2/22/2022 7:07:26 AM')
$my_vertices = $my_edges.getEdgeEndpoints()
$my_graph = $my_edges + $my_vertices
export > /spade-data2/Jigsaw/ransomware/47d49ac2d3c5bb33137106f9c3b91e35/2022-02-22-07-07-26.dot
dump all $my_graph
$my_edges = $my_lineage.getEdge(datetime = '2/22/2022 7:07:27 AM')
$my_vertices = $my_edges.getEdgeEndpoints()
$my_graph = $my_edges + $my_vertices
export > /spade-data2/Jigsaw/ransomware/47d49ac2d3c5bb33137106f9c3b91e35/2022-02-22-07-07-27.dot
dump all $my_graph
$my_process = vertices('01cfcdcfb41e5095763c74d2aa3968d1')
$my_lineage = $base.getLineage($my_process, 1, 'b')
$my_edges = $my_lineage.getEdge(datetime = '2/22/2022 7:07:25 AM')
$my_vertices = $my_edges.getEdgeEndpoints()
$my_graph = $my_edges + $my_vertices
export > /spade-data2/Jigsaw/ransomware/01cfcdcfb41e5095763c74d2aa3968d1/2022-02-22-07-07-25.dot
dump all $my_graph
$my_edges = $my_lineage.getEdge(datetime = '2/22/2022 7:07:28 AM')
$my_vertices = $my_edges.getEdgeEndpoints()
$my_graph = $my_edges + $my_vertices
export > /spade-data2/Jigsaw/ransomware/01cfcdcfb41e5095763c74d2aa3968d1/2022-02-22-07-07-28.dot
dump all $my_graph
$my_edges = $my_lineage.getEdge(datetime = '2/22/2022 7:07:27 AM')
$my_vertices = $my_edges.getEdgeEndpoints()
$my_graph = $my_edges + $my_vertices
export > /spade-data2/Jigsaw/ransomware/01cfcdcfb41e5095763c74d2aa3968d1/2022-02-22-07-07-27.dot
dump all $my_graph
exit

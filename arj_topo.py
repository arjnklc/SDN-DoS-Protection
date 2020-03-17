from mininet.topo import Topo


# to run:
# sudo mn --custom arj_topo.py --topo arj_topo --controller remote,ip=172.17.0.7



class Arj_Topology( Topo ):
    def __init__( self ):
        Topo.__init__( self )

        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        s1 = self.addSwitch('s1')

        self.addLink(h1,s1)
        self.addLink(h2,s1)


topos = {'arj_topo': (lambda: Arj_Topology())}
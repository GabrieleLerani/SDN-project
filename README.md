# 1 - Traffic engineering in a datacenter network
The goal of the first part of the project is to optimize the traffic of a datacenter network with leaf and spine switch using SDN and openflow paradigm.
If the network is managed according to the classical L2 paradigm, then there is a large waste of bandwidth, due to the fact
that the Spanning Tree Protocol (SPT) must be used in order to remove loops in the physical topology. It implies that the 
capacity of the network links that do not belong to the spanning tree is wasted.
The suggested SDN solution aims to overcome this limitation by dynamically configuring paths based on the actual traffic flows.

![Screenshot from 2024-01-27 15-52-14](https://github.com/GabrieleLerani/SDN-project/assets/92364167/bb64cb3d-87fe-4d78-800e-453200ba5f5f)

## Technologies
All the simulations have been executed in mininet and kathara, the SDN controller (full python) used is pox.
## Results
The results were compared with a traditional L2 network where the bandwidth waste is around 40%. Under the SDN approach, the network can achieve 100% of 
its total bandwidth, resulting in improved efficiency and reduced waste compared to the classical L2 paradigm

# 2 - SFC architecture with P4
The second part aims to implement SFC using P4 programming, defining the behavior of switches to achieve the specified traffic steering through Service Functions based on the NSH. 
The SFC components include the Classifier (CL), Service Function Forwarder (SFF), 
and the use of pre-configured tunnels for overlay connectivity

![Screenshot from 2024-01-27 15-51-32](https://github.com/GabrieleLerani/SDN-project/assets/92364167/cb8af7aa-f6bc-4763-9fca-eda23c42a9b1)

## Technologies
All the simulations have been executed in mininet and kathara, the programmable dataplane is managed using P4, traffic analysis is made with wireshark.
## Results
The proposed solution allows for dynamic service composition, in addition policies can be adjusted in real-time based on changing conditions
or requirements.

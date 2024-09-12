
# SecShield: An IoT Access Control Framework with Edge Caching using Software Defined Network #

SecShield is a novel Software Defined Network (SDN)-based framework, particularly designed for IoT environments. SecShield operates by evaluating access requests and granting access to IoT services only when the set of defined access policies are satisfied. Utilizing the Attribute-Based Access Control (ABAC) model, SecShield specifies fine-grained access policies for IoT services and employs an algorithm for evaluating access requests. Additionally, the framework incorporates a local cache at the edge of the IoT network, enhanced with a Least Recently Used (LRU) algorithm, to optimize the process of access request evaluation. 

## Configuration &amp; System Requirements ##

 SecShield requires an installation of **Java JDK version 17**. To resolve the project dependencies, you will need to have **NetBeans version 16 or higher** installed. For a manual start, these variables - as well as multiple variables concerning the simulation setting - can be configured in the Config.java  file. Overall, you can configure the following variables and files:

> - **Method:** Select ‘Base’ if you want to run the Base framework, or ‘Proposed' if you want to run the SecShield framework. The Base framework is the implementation of the framework proposed in Bander Alzahrani and Nikos Fotiou, 'Enhancing Internet of Things Security Using Software-Defined Networking,' Journal of Systems Architecture 110 (2022): 101779.
> - **CoapServer_Number::** Numberَ of Coap Servers.
> - **CoapClient_Number:**  Number of Coap Clients.
> - **Packets:**  Number of access requests. A new workload file must also be created based on the new value of this variable.
> - 
__Please note:__ The VirtualTopologyGenerator class in CloudSimSDN generates the dataset that we used as the workload. Object and Subject Attributes are set in sheets 1 and 2 of the Network_access.xls file, and access policies are set in the ABAC_Policy_Set.csv file. Additionally, the results are displayed in the Results.xls file.


 

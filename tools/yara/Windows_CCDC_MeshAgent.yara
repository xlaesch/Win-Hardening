rule MeshAgent
{
	meta:
		author = "Oleksandr Maniukhin"
        organization = "CCDC RIT"
		description = "Core strings for MeshAgent"
        threat_name = "MeshAgent"
        os = "Windows"
        created = "2025-09-16"
        last_modified = "2025-09-16"

    strings:
        $a1  = "require('win-authenticode-opus')(process.execPath);"
        $a2  = "fakeUpdate"
        $a3  = "mesh_linumshx"
        $a4  = "mesh_limshx"
        $a5  = "meshServiceName"
        $a6  = "MeshCentral"
        $a7  = "AgentHash"
        $a8  = "MeshId"
        $a9  = "MeshServerUrl"
        $a10 = "MeshServerId"
        $a11 = "DiagnosticAgentNodeId"
        $a12 = "NodeID"
        $a13 = "AgentCapabilities"
        $a14 = "MeshName=TacticalRMM"
        $a15 = "MeshType=2"
        $a16 = "MeshServer=wss://mesh."
        $a17 = "MeshAgent_Slave: Command:"
        $a18 = "MeshAgent_Slave: Added module"
        $a19 = "MeshAgent_Slave: Created Java Script Engine"
        $a20 = "Mesh Agent background service"
        $a21 = "o=MeshAgent %u 0 IN IP4 0.0.0.0"
        $a22 = "MeshAgent [GUARDPOST]"
        $a23 = "MeshAgent [KVM]"
        $a24 = "MeshAgent [P2P]"

        // Regex for IDs (flexible, matches any hex of sufficient length)
        $a_meshid   = /MeshID=0x[0-9A-F]{64,}/
        $a_serverid = /ServerID=[0-9A-F]{64,}/
    
    condition:
        ($a_meshid or $a_serverid) and (10 of ($a*))
}

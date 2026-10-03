rule TacticalRMM
{
	meta:
		author = "Oleksandr Maniukhin"
        organization = "CCDC RIT"
		description = "Core strings for TacticalRMM agent"
        threat_name = "TacticalRMM"
        os = "Windows"
        created = "2025-09-16"
        last_modified = "2025-09-16"

    strings:
        $a1  = "Tactical RMM Agent"
        $a2  = "tacticalrmm.exe"
        $a3  = "MeshInstaller"
        $a4  = "MeshSystemEXE"
        $a5  = "debugCall128"
        $a6  = "debugCall256"
        $a7  = "debugCall512"
        $a8  = "debugCall1024"
        $a9  = "/api/v3/meshexe/"
        $a10 = "github.com/amidaware/rmmagent"
        $a11 = "github.com/nats-io/nkeys"
        $a12 = "github.com/nats-io/nats.go"
        $a13 = "AmidaWare Inc" wide
        $a14 = "UserAgent"
        $a15 = "AgentHeader"
        $a16 = "AgentUpdate"

    condition:
        8 of ($a*)
}
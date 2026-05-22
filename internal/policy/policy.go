package policy

func Evaluate(comm string) string {

	switch comm {

	case "bash":
		return "interactive shell execution"

	case "sh":
		return "shell execution"

	case "nc":
		return "possible reverse shell"

	case "chmod":
		return "permission modification"

	case "runc":
		return "container runtime activity"

	case "nmap":
		return "network reconnaissance"

	default:
		return "normal"
	}
}

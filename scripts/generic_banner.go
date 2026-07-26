package main

import "fmt"

func Run(target map[string]interface{}) map[string]string {
	output := make(map[string]string)

	ip, okIP := target["IP"].(string)
	port, okPort := target["Port"].(int)

	if !okIP || !okPort {
		output["error"] = "Invalid target format received by script"
		return output
	}

	output["message"] = fmt.Sprintf("Script executed on open port %d at %s!", port, ip)

	return output
}

package search

// SecurityTerms is the domain-specific dictionary for security terminology.
var SecurityTerms = []string{
	// Multi-word Chinese terms (longest first)
	"远程代码执行", "跨站请求伪造", "服务端请求伪造", "本地文件包含",
	"远程文件包含", "XML外部实体", "不安全反序列化", "服务器端模板注入",
	"操作系统命令注入", "二阶SQL注入", "基于时间的盲注", "基于布尔的盲注",
	"基于报错的注入", "基于联合查询注入", "HTTP请求走私", "HTTP参数污染",
	"服务端包含注入", "跨站脚本攻击", "横向移动", "权限提升",
	"持久化", "命令执行", "代码执行", "文件上传", "文件包含",
	"目录遍历", "信息泄露", "逻辑漏洞", "越权访问", "未授权访问",
	"弱口令", "暴力破解", "密码喷洒", "凭据填充", "会话劫持",
	"会话固定", "中间人攻击", "域名劫持", "子域名接管", "DNS重绑定",
	"供应链攻击", "水坑攻击", "钓鱼攻击", "社会工程", "内网渗透",
	"域渗透", "红队", "蓝队", "紫队", "漏洞扫描", "漏洞利用",
	"后渗透", "免杀技术", "反弹Shell", "提权漏洞",
	// Two-char Chinese terms
	"注入", "提权", "爆破", "枚举", "扫描", "渗透", "绕过",
	"利用", "劫持", "伪造", "欺骗", "嗅探", "重放", "逆向",
	"脱壳", "加壳", "混淆", "反编译",
	// English terms
	"SQL Injection", "Cross-Site Scripting", "XSS", "CSRF", "SSRF",
	"XXE", "LFI", "RFI", "RCE", "IDOR", "SSTI", "CRLF",
	"LDAP Injection", "NoSQL Injection", "Command Injection",
	"Path Traversal", "Directory Traversal", "File Upload",
	"Deserialization", "Prototype Pollution", "DOM Clobbering",
	"HTTP Smuggling", "HTTP Parameter Pollution", "HPP",
	"Server-Side Includes", "SSI", "Open Redirect",
	"Clickjacking", "CORS Misconfiguration", "JWT",
	"OAuth", "SAML", "Kerberos", "Kerberoasting", "AS-REP Roasting",
	"Pass-the-Hash", "Pass-the-Ticket", "Golden Ticket", "Silver Ticket",
	"DCSync", "DCShadow", "BloodHound", "Mimikatz", "Rubeus",
	"Responder", "Impacket", "CrackMapExec", "Evil-WinRM",
	"Metasploit", "Cobalt Strike", "Burp Suite",
	"Nmap", "Masscan", "Nuclei", "SQLMap", "Nikto", "Gobuster",
	"Ffuf", "Dirsearch", "Subfinder", "Amass", "httpx",
	"OWASP", "MITRE ATT&CK", "CVE", "CWE", "CVSS",
	"Privilege Escalation", "Lateral Movement", "Persistence",
	"Defense Evasion", "Credential Access", "Initial Access",
	"Reconnaissance", "Resource Development", "Execution",
	"Discovery", "Collection", "Exfiltration",
	"Command and Control", "C2", "Reverse Shell", "Web Shell",
	"Bind Shell", "Meterpreter", "Beacon",
	"Buffer Overflow", "Heap Overflow", "Stack Overflow",
	"Use After Free", "Format String", "Race Condition",
	"TOCTOU", "Integer Overflow", "Null Pointer Dereference",
	"Active Directory", "Domain Controller", "Group Policy",
	"WMI", "PSExec", "DCOM", "WinRM", "SMB", "RDP", "SSH",
	"AWS", "Azure", "GCP", "S3 Bucket", "EC2", "IAM",
	"Lambda", "CloudTrail", "Kubernetes", "Docker",
	"Container Escape", "SSRF to Cloud Metadata",
	"WAF", "IDS", "IPS", "EDR", "SIEM", "SOC",
	"Brute Force", "Dictionary Attack", "Rainbow Table",
	"Hashcat", "John the Ripper", "Hydra",
	"Phishing", "Spear Phishing", "Whaling",
	"Vishing", "Smishing", "Watering Hole",
	"Supply Chain", "Typosquatting",
	"Subdomain Takeover", "DNS Rebinding",
	"DNSSEC", "Zone Transfer",
}

var securityTermMap map[string]struct{}

func init() {
	securityTermMap = make(map[string]struct{}, len(SecurityTerms))
	for _, t := range SecurityTerms {
		securityTermMap[toLower(t)] = struct{}{}
	}
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		} else {
			b[i] = c
		}
	}
	return string(b)
}

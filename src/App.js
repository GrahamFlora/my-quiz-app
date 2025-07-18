import React, { useState, useEffect, useCallback, useRef } from 'react';

// =================================================================================
// === DATA & CONFIGURATION ========================================================
// =================================================================================
 const masterQuestions = [
    {
      questionText: 'Which of the following threat actors is the most likely to be hired by a foreign government to attack critical systems located in other countries?',
      answerOptions: [
        { answerText: 'Hacktivist', isCorrect: false },
        { answerText: 'Whistleblower', isCorrect: false },
        { answerText: 'Organized crime', isCorrect: true },
        { answerText: 'Unskilled attacker', isCorrect: false },
      ],
  explanation: 'C. Organized crime Organized crime groups often have the resources, expertise, and networks to carry out sophisticated cyber attacks on behalf of governments or other entities for financial gain or political motives.'
    },
    {
      questionText: 'Which of the following is used to add extra complexity before using a one-way data transformation algorithm?',
      answerOptions: [
        { answerText: 'Key stretching', isCorrect: false },
        { answerText: 'Data masking', isCorrect: false },
        { answerText: 'Steganography', isCorrect: false },
        { answerText: 'Salting', isCorrect: true },
      ],
    explanation: 'D. Salting Salting involves adding random data to the input of a one-way hash function to ensure that the same input will produce different hash values, thus making it more difficult for attackers to use precomputed hash tables (rainbow tables) to reverse engineer the original input.'
  },
    {
      questionText: 'An employee clicked a link in an email from a payment website that asked the employee to update contact information. The employee entered the log-in information but received a “page not found” error message. Which of the following types of social engineering attacks occurred?',
      answerOptions: [
        { answerText: 'Brand impersonation', isCorrect: false },
        { answerText: 'Pretexting', isCorrect: false },
        { answerText: 'Typosquatting', isCorrect: false },
        { answerText: 'Phishing', isCorrect: true },
      ],
    explanation: 'Phishing is the fraudulent practice of sending emails, or other messages to cause an individual to reveal personal information. This question does not specify if this email was pretexting to butter up the employee, or make email more convincing (pretexting), nor does it specify this email being a trusted brand, or waiting on employee to type incorrectly to steal information.'
  },
    {
      questionText: 'An enterprise is trying to limit outbound DNS traffic originating from its internal network. Outbound DNS requests will only be allowed from one device with the IP address 10.50.10.25. Which of the following firewall ACLs will accomplish this goal?',
      answerOptions: [
        { answerText: 'Access list outbound permit 0.0.0.0/0 0.0.0.0/0 port 53 Access list outbound deny 10.50.10.25/32 0.0.0.0/0 port 53', isCorrect: false },
        { answerText: 'Access list outbound permit 0.0.0.0/0 10.50.10.25/32 port 53 Access list outbound deny 0.0.0.0/0 0.0.0.0/0 port 53', isCorrect: false },
        { answerText: 'Access list outbound permit 0.0.0.0/0 0.0.0.0/0 port 53 Access list outbound deny 0.0.0.0/0 10.50.10.25/32 port 53', isCorrect: false },
        { answerText: 'Access list outbound permit 10.50.10.25/32 0.0.0.0/0 port 53 Access list outbound deny 0.0.0.0/0 0.0.0.0/0 port 53', isCorrect: true },
      ],
    explanation: 'The correct ACL (Access Control List) to accomplish the goal of limiting outbound DNS traffic originating from the internal network to only one device with the IP address 10.50.10.25 would be option D: Copy code Access list outbound permit 10.50.10.25/32 0.0.0.0/0 port 53 Access list outbound deny 0.0.0.0/0 0.0.0.0/0 port 53 This configuration allows outbound DNS requests from the specific IP address 10.50.10.25 and denies outbound DNS requests from any other IP address.'
  },
    {
      questionText: 'A data administrator is configuring authentication for a SaaS application and would like to reduce the number of credentials employees need to maintain. The company prefers to use domain credentials to access new SaaS applications. Which of the following methods would allow this functionality?',
      answerOptions: [
        { answerText: 'SSO', isCorrect: true },
        { answerText: 'LEAP', isCorrect: false },
        { answerText: 'MFA', isCorrect: false },
        { answerText: 'PEAP', isCorrect: false },
      ],
    explanation: 'A. SSO (Single Sign-On) Single Sign-On (SSO) enables users to authenticate once with their domain credentials and then access multiple applications without needing to re-enter their credentials each time. This aligns with the company\'s preference to use domain credentials and reduces the burden of managing multiple sets of credentials for different applications.'
  },
    {
      questionText: 'Which of the following scenarios describes a possible business email compromise attack?',
      answerOptions: [
        { answerText: 'An employee receives a gift card request in an email that has an executive’s name in the display field of the email.', isCorrect: false },
        { answerText: 'Employees who open an email attachment receive messages demanding payment in order to access files.', isCorrect: false },
        { answerText: 'A service desk employee receives an email from the HR director asking for log-in credentials to a cloud administrator account.', isCorrect: true },
        { answerText: 'An employee receives an email with a link to a phishing site that is designed to look like the company’s email portal.', isCorrect: false },
      ],
    explanation: 'C. In a BEC attack, the attacker typically impersonates a high-ranking executive or authority figure within the organization and requests sensitive information or actions from employees. In this case, the HR director is requesting log-in credentials for a cloud administrator account, which is a classic example of BEC where the attacker seeks to gain access to privileged accounts through deception.'
  },
    {
      questionText: 'A company prevented direct access from the database administrators’ workstations to the network segment that contains database servers. Which of the following should a database administrator use to access the database servers?',
      answerOptions: [
        { answerText: 'Jump server', isCorrect: true },
        { answerText: 'RADIUS', isCorrect: false },
        { answerText: 'HSM', isCorrect: false },
        { answerText: 'Load balancer', isCorrect: false },
      ],
    explanation: 'Maybe it\'s my ADHD but that is worded in a way that is very difficult to understand,'
  },
    {
      questionText: 'An organization’s internet-facing website was compromised when an attacker exploited a buffer overflow. Which of the following should the organization deploy to best protect against similar attacks in the future?',
      answerOptions: [
        { answerText: 'NGFW', isCorrect: false },
        { answerText: 'WAF', isCorrect: true },
        { answerText: 'TLS', isCorrect: false },
        { answerText: 'SD-WAN', isCorrect: false },
      ],
    explanation: 'B is the correct one B. WAF (Web Application Firewall) A. NGFW (Next-Generation Firewall) C. TLS (Transport Layer Security) D. SD-WAN (Software-Defined Wide Area Network)'
  },
    {
      questionText: 'An administrator notices that several users are logging in from suspicious IP addresses. After speaking with the users, the administrator determines that the employees were not logging in from those IP addresses and resets the affected users’ passwords. Which of the following should the administrator implement to prevent this type of attack from succeeding in the future?',
      answerOptions: [
        { answerText: 'Multifactor authentication', isCorrect: true },
        { answerText: 'Permissions assignment', isCorrect: false },
        { answerText: 'Access management', isCorrect: false },
        { answerText: 'Password complexity', isCorrect: false },
      ],
    explanation: 'A. Multifactor; there\'s a need to add "something you have", apart from "something you (they) know".'
  },
    {
      questionText: 'An employee receives a text message that appears to have been sent by the payroll department and is asking for credential verification. Which of the following social engineering techniques are being attempted? (Choose two.)',
      answerOptions: [
        { answerText: 'Typosquatting', isCorrect: false },
        { answerText: 'Phishing', isCorrect: false },
        { answerText: 'Impersonation', isCorrect: true },
        { answerText: 'Vishing', isCorrect: false },
        { answerText: 'Smishing', isCorrect: true },
        { answerText: 'Misinformation', isCorrect: false },
      ],
    explanation: 'In this scenario, where an employee receives a text message appearing to be from the payroll department asking for credential verification, the following social engineering techniques are being attempted: C. Impersonation - The attacker is pretending to be a trusted entity (the payroll department) to gain the employee\'s trust and obtain their credentials. E. Smishing - Smishing (SMS phishing) involves sending fraudulent text messages to trick individuals into revealing personal information, such as credentials, by clicking on a link or responding to the message.'
  },
    {
      questionText: 'Several employees received a fraudulent text message from someone claiming to be the Chief Executive Officer (CEO). The message stated:“I’m in an airport right now with no access to email. I need you to buy gift cards for employee recognition awards. Please send the gift cards to following email address.”Which of the following are the best responses to this situation? (Choose two).',
      answerOptions: [
        { answerText: 'Cancel current employee recognition gift cards.', isCorrect: false },
        { answerText: 'Add a smishing exercise to the annual company training.', isCorrect: true },
        { answerText: 'Issue a general email warning to the company.', isCorrect: true },
        { answerText: 'Have the CEO change phone numbers.', isCorrect: false },
        { answerText: 'Conduct a forensic investigation on the CEO’s phone.', isCorrect: false },
        { answerText: 'Implement mobile device management.', isCorrect: false },
      ],
    explanation: 'It is already known that the message is not being sent from the CEO, & awareness of this attack should be known among the company by using the proper training to identify when an attacker is smishing using employee likeness. It is not known if devices are compromised, but if employees are aware of the situation, then that can be figured out as well.'
  },
    {
      questionText: 'A company is required to use certified hardware when building networks. Which of the following best addresses the risks associated with procuring counterfeit hardware?',
      answerOptions: [
        { answerText: 'A thorough analysis of the supply chain', isCorrect: true },
        { answerText: 'A legally enforceable corporate acquisition policy', isCorrect: false },
        { answerText: 'A right to audit clause in vendor contracts and SOWs', isCorrect: false },
        { answerText: 'An in-depth penetration test of all suppliers and vendors', isCorrect: false },
      ],
    explanation: 'An analysis would safely address if their was a lack of reliability, or authenticity when procuring hardware from a supplier to protect the company.'
  },
    {
      questionText: 'Which of the following provides the details about the terms of a test with a third-party penetration tester?',
      answerOptions: [
        { answerText: 'Rules of engagement', isCorrect: true },
        { answerText: 'Supply chain analysis', isCorrect: false },
        { answerText: 'Right to audit clause', isCorrect: false },
        { answerText: 'Due diligence', isCorrect: false },
      ],
    explanation: 'The correct option that provides details about the terms of a test with a third-party penetration tester is: A. Rules of engagement Rules of engagement (RoE) outline the scope, objectives, limitations, and boundaries of the penetration test. This document ensures both parties understand what is allowed and expected during the testing process, including which systems can be tested, the methods to be used, the timing of the tests, and how the results will be reported and handled. - B: This involves assessing the risks associated with the supply chain and third-party vendors, not specifically the terms of a penetration test. - C: This clause in a contract allows one party to audit the other, typically related to compliance and security practices, but does not detail the terms of a penetration test. - D. This is the process of investigating and evaluating a business or person before signing a contract, but it doesn\'t provide the specific terms of a penetration test.'
  },
    {
      questionText: 'A penetration tester begins an engagement by performing port and service scans against the client environment according to the rules of engagement. Which of the following reconnaissance types is the tester performing?',
      answerOptions: [
        { answerText: 'Active', isCorrect: true },
        { answerText: 'Passive', isCorrect: false },
        { answerText: 'Defensive', isCorrect: false },
        { answerText: 'Offensive', isCorrect: false },
      ],
    explanation: 'A. Active Active reconnaissance involves actively probing and scanning the target environment to gather information. This typically includes activities such as port and service scans, vulnerability scans, and other direct interactions with the target systems to identify potential weaknesses or entry points. Passive reconnaissance, on the other hand, involves gathering information without directly interacting with the target systems, such as monitoring network traffic or analyzing publicly available information. Options C and D, defensive and offensive reconnaissance, respectively, are not standard reconnaissance types typically used in the context of penetration testing.'
  },
    {
      questionText: 'Which of the following is required for an organization to properly manage its restore process in the event of system failure?',
      answerOptions: [
        { answerText: 'IRP', isCorrect: false },
        { answerText: 'DRP', isCorrect: true },
        { answerText: 'RPO', isCorrect: false },
        { answerText: 'SDLC', isCorrect: false },
      ],
    explanation: 'RPO would cover amount of data that is expected to be recovered given a failure while DRP encompasses the whole recovery process necessary to restore the system.'
  },
    {
      questionText: 'Which of the following vulnerabilities is associated with installing software outside of a manufacturer’s approved software repository?',
      answerOptions: [
        { answerText: 'Jailbreaking', isCorrect: false },
        { answerText: 'Memory injection', isCorrect: false },
        { answerText: 'Resource reuse', isCorrect: false },
        { answerText: 'Side loading', isCorrect: true },
      ],
    explanation: 'D. Side loading is the act of installing software outside of the manufacturers approved repository.'
  },
    {
      questionText: 'An analyst is reviewing logs showing multiple failed login attempts for several different user accounts, each from a different IP address, all trying the same one or two passwords. Which of the following attacks is most likely occurring?',
      answerOptions: [
        { answerText: 'Password spraying', isCorrect: true },
        { answerText: 'Account forgery', isCorrect: false },
        { answerText: 'Pass-the-hash', isCorrect: false },
        { answerText: 'Brute-force', isCorrect: false },
      ],
    explanation: 'A password spraying attack is a type of brute-force attack where an attacker tries a small number of common passwords against many different user accounts. The attacker uses a bot to repeatedly attempt these passwords until they find a successful login.'
  },
    {
      questionText: 'An analyst is evaluating the implementation of Zero Trust principles within the data plane. Which of the following would be most relevant for the analyst to evaluate?',
      answerOptions: [
        { answerText: 'Secured zones', isCorrect: false },
        { answerText: 'Subject role', isCorrect: true },
        { answerText: 'Adaptive identity', isCorrect: false },
        { answerText: 'Threat scope reduction', isCorrect: false },
      ],
    explanation: 'A. Secured Zones Explanation: In the context of implementing Zero Trust principles within the data plane, secured zones are most relevant. Zero Trust principles emphasize the need to eliminate implicit trust and enforce strict access controls. By evaluating and implementing secured zones, an organization can ensure that data is compartmentalized and that access is tightly controlled, aligning with the core tenets of Zero Trust. This approach helps to contain threats and limit lateral movement within the network, providing a strong foundation for a Zero Trust architecture.'
  },
    {
      questionText: 'An engineer needs to find a solution that creates an added layer of security by preventing unauthorized access to internal company resources. Which of the following would be the best solution?',
      answerOptions: [
        { answerText: 'RDP server', isCorrect: false },
        { answerText: 'Jump server', isCorrect: true },
        { answerText: 'Proxy server', isCorrect: false },
        { answerText: 'Hypervisor', isCorrect: false },
      ],
    explanation: 'A Proxy Server is used to fetch Internet content requested for access by internal users, & can also be configured to cache content for a specified amount of time so that subsequent requests for content are satisfied locally instead of from the Internet. A Jump Server protects internal company resources that would have no reason to be accessed by the outside.'
  },
    {
      questionText: 'A company’s web filter is configured to scan the URL for strings and deny access when matches are found. Which of the following search strings should an analyst employ to prohibit access to non-encrypted websites?',
      answerOptions: [
        { answerText: 'encryption=off', isCorrect: false },
        { answerText: 'http://', isCorrect: true },
        { answerText: 'www.*.com', isCorrect: false },
        { answerText: ':443', isCorrect: false },
      ],
    explanation: 'Blocking the string "http://" is the best way to prohibit access to non-encrypted websites. Non-encrypted websites use HTTP, while encrypted websites use HTTPS. This ensures only non-encrypted traffic is blocked without affecting encrypted websites. A. encryption=off: Not a consistent identifier for non-encrypted websites. C. www.*.com: Too broad, blocks both encrypted and non-encrypted websites. D. :443: Indicates HTTPS traffic, blocking it would deny access to encrypted websites.'
  },
    {
      questionText: 'During a security incident, the security operations team identified sustained network traffic from a malicious IP address: 10.1.4.9. A security analyst is creating an inbound firewall rule to block the IP address from accessing the organization’s network. Which of the following fulfills this request?',
      answerOptions: [
        { answerText: 'access-list inbound deny ip source 0.0.0.0/0 destination 10.1.4.9/32', isCorrect: false },
        { answerText: 'access-list inbound deny ip source 10.1.4.9/32 destination 0.0.0.0/0', isCorrect: true },
        { answerText: 'access-list inbound permit ip source 10.1.4.9/32 destination 0.0.0.0/0', isCorrect: false },
        { answerText: 'access-list inbound permit ip source 0.0.0.0/0 destination 10.1.4.9/32', isCorrect: false },
      ],
    explanation: 'Source: 10.1.4.9/32 specifies the exact malicious IP address to block. Destination: 0.0.0.0/0 indicates all possible destinations within the network. Action: deny specifies that traffic from this source IP should be blocked. • Scenario Application: Blocking Malicious IP: This rule effectively blocks any incoming traffic from the IP address 10.1.4.9 from accessing any part of the network. Inbound Rule: As an inbound rule, it prevents traffic from the specified IP from entering the network, which aligns with the requirement to block the malicious IP. This rule directly addresses the need to block the specified IP address, fulfilling the requirement by denying access to all destinations, effectively preventing any communication from the malicious IP.'
  },
    {
      questionText: 'A company needs to provide administrative access to internal resources while minimizing the traffic allowed through the security boundary. Which of the following methods is most secure?',
      answerOptions: [
        { answerText: 'Implementing a bastion host', isCorrect: true },
        { answerText: 'Deploying a perimeter network', isCorrect: false },
        { answerText: 'Installing a WAF', isCorrect: false },
        { answerText: 'Utilizing single sign-on', isCorrect: false },
      ],
    explanation: 'Implementing a bastion host: A bastion host is a highly secured server located on a perimeter network (also known as a DMZ) that is designed to withstand attacks. It acts as a gateway between internal and external networks, allowing access only to specific services and applications. Users must authenticate themselves to the bastion host before accessing internal resources. This option provides a controlled entry point into the internal network, reducing the attack surface.'
  },
    {
      questionText: 'A security analyst is reviewing alerts in the SIEM related to potential malicious network traffic coming from an employee’s corporate laptop. The security analyst has determined that additional data about the executable running on the machine is necessary to continue the investigation. Which of the following logs should the analyst use as a data source?',
      answerOptions: [
        { answerText: 'Application', isCorrect: false },
        { answerText: 'IPS/IDS', isCorrect: false },
        { answerText: 'Network', isCorrect: false },
        { answerText: 'Endpoint', isCorrect: true },
      ],
    explanation: 'Endpoint logs: Endpoint logs, also known as host logs, record events and activities that occur on individual endpoints (such as laptops, desktops, or servers). These logs can include information about processes, applications, system events, user logins, file accesses, and more. Endpoint logs are a valuable source of data for investigating security incidents on specific devices, including information about the executables running on the machine. For the investigation described in the scenario, the most appropriate data source for obtaining additional information about the executable running on the employee\'s corporate laptop is Endpoint logs. Endpoint logs can provide detailed insights into the processes and executables running on the machine, helping the security analyst to further analyze and respond to the potential security threat.'
  },
    {
      questionText: 'A cyber operations team informs a security analyst about a new tactic malicious actors are using to compromise networks.SIEM alerts have not yet been configured. Which of the following best describes what the security analyst should do to identify this behavior?',
      answerOptions: [
        { answerText: 'Digital forensics', isCorrect: false },
        { answerText: 'E-discovery', isCorrect: false },
        { answerText: 'Incident response', isCorrect: false },
        { answerText: 'Threat hunting', isCorrect: true },
      ],
    explanation: 'Threat hunting: Threat hunting involves proactively searching for and identifying potential security threats or indicators of compromise (IOCs) within an organization\'s network environment. It typically involves the use of advanced analytics, threat intelligence, and specialized tools to detect suspicious behavior or anomalies that may indicate the presence of a threat actor. In the scenario described, where SIEM alerts have not yet been configured to detect the new tactic malicious actors are using, the most appropriate action for the security analyst is Threat hunting. By engaging in threat hunting activities, the security analyst can proactively search for signs of the new tactic within the network environment, helping to identify and mitigate potential security risks before they escalate into full-blown incidents.'
  },
    {
      questionText: 'A company purchased cyber insurance to address items listed on the risk register. Which of the following strategies does this represent?',
      answerOptions: [
        { answerText: 'Accept', isCorrect: false },
        { answerText: 'Transfer', isCorrect: true },
        { answerText: 'Mitigate', isCorrect: false },
        { answerText: 'Avoid', isCorrect: false },
      ],
    explanation: 'Transfer: Transferring a risk involves shifting some or all of the risk to another party, such as an insurance provider, through contractual agreements or financial arrangements. If the company purchases cyber insurance to address items listed on the risk register, it represents a risk transfer strategy. The company is transferring the financial burden of potential cyber incidents to the insurance provider, who will compensate the company for covered losses. Given the scenario described, the strategy represented by the company\'s purchase of cyber insurance to address items listed on the risk register is Transfer. The company is transferring some of the financial consequences of potential cyber incidents to the insurance provider through the purchase of insurance coverage.'
  },
    {
      questionText: 'A security administrator would like to protect data on employees’ laptops. Which of the following encryption techniques should the security administrator use?',
      answerOptions: [
        { answerText: 'Partition', isCorrect: false },
        { answerText: 'Asymmetric', isCorrect: false },
        { answerText: 'Full disk', isCorrect: true },
        { answerText: 'Database', isCorrect: false },
      ],
    explanation: 'The answer is C - Fulldisk encryption, this encrypts the whole storage drive of the device, including OS, files, app data, etc. the reason its not the other options partition encryption - only encrypts the partition, meaning if there are multiple partitions then some of them could be left unencrypted and a threat actor could steal data in them. Asymmetric encryption - is an encryption technique using Public Key, private key methodology. Database encryption - is used to encrypt databases (schema) or data within the databases.'
  },
    {
      questionText: 'Which of the following security control types does an acceptable use policy best represent?',
      answerOptions: [
        { answerText: 'Detective', isCorrect: false },
        { answerText: 'Compensating', isCorrect: false },
        { answerText: 'Corrective', isCorrect: false },
        { answerText: 'Preventive', isCorrect: true },
      ],
    explanation: 'D. Preventive AUP is pretty obviously trying to prevent things from happening. It\'s not A. Detective because it doesn\'t detect anything. It\'s a policy. It\'s not B. Compensating because it isn\'t making up for any other policy included in the question. It\'s not C. Corrective because it doesn\'t correct anything on it\'s own, it\'s simply a policy that is to be followed. So it could only be D. Preventive, as it prevents people from doing things that might compromise the network.'
  },
    {
      questionText: 'An IT manager informs the entire help desk staff that only the IT manager and the help desk lead will have access to the administrator console of the help desk software. Which of the following security techniques is the IT manager setting up?',
      answerOptions: [
        { answerText: 'Hardening', isCorrect: false },
        { answerText: 'Employee monitoring', isCorrect: false },
        { answerText: 'Configuration enforcement', isCorrect: false },
        { answerText: 'Least privilege', isCorrect: true },
      ],
    explanation: 'Least privilege: Least privilege is a security principle that states that users should only be granted the minimum level of access or permissions necessary to perform their job functions. By restricting access to the administrator console of the help desk software to only the IT manager and the help desk lead, the IT manager is adhering to the principle of least privilege, ensuring that only those individuals who require administrative access have it, thereby reducing the risk of unauthorized access and potential misuse. Given the scenario described, the security technique that the IT manager is setting up by restricting access to the administrator console of the help desk software is Least privilege. This approach aligns with the principle of least privilege by granting administrative access only to individuals who need it to perform their job responsibilities.'
  },
    {
      questionText: 'Which of the following is the most likely to be used to document risks, responsible parties, and thresholds?',
      answerOptions: [
        { answerText: 'Risk tolerance', isCorrect: false },
        { answerText: 'Risk transfer', isCorrect: false },
        { answerText: 'Risk register', isCorrect: true },
        { answerText: 'Risk analysis', isCorrect: false },
      ],
    explanation: 'Think of register as registry, all the details of stuff'
  },
    {
      questionText: 'Which of the following should a security administrator adhere to when setting up a new set of firewall rules?',
      answerOptions: [
        { answerText: 'Disaster recovery plan', isCorrect: false },
        { answerText: 'Incident response procedure', isCorrect: false },
        { answerText: 'Business continuity plan', isCorrect: false },
        { answerText: 'Change management procedure', isCorrect: true },
      ],
    explanation: 'The keyword is "new" firewall rules. Any change must be adhered to change management procedures.'
  },
    {
      questionText: 'A company is expanding its threat surface program and allowing individuals to security test the company’s internet-facing application. The company will compensate researchers based on the vulnerabilities discovered. Which of the following best describes the program the company is setting up?',
      answerOptions: [
        { answerText: 'Open-source intelligence', isCorrect: false },
        { answerText: 'Bug bounty', isCorrect: true },
        { answerText: 'Red team', isCorrect: false },
        { answerText: 'Penetration testing', isCorrect: false },
      ],
    explanation: 'B. Bug bounty'
  },
    {
      questionText: 'Which of the following threat actors is the most likely to use large financial resources to attack critical systems located in other countries?',
      answerOptions: [
        { answerText: 'Insider', isCorrect: false },
        { answerText: 'Unskilled attacker', isCorrect: false },
        { answerText: 'Nation-state', isCorrect: true },
        { answerText: 'Hacktivist', isCorrect: false },
      ],
    explanation: 'Think of China right now, they hacking into CIKR and are heavily funded. NATION STATE.'
  },
    {
      questionText: 'Which of the following enables the use of an input field to run commands that can view or manipulate data?',
      answerOptions: [
        { answerText: 'Cross-site scripting', isCorrect: false },
        { answerText: 'Side loading', isCorrect: false },
        { answerText: 'Buffer overflow', isCorrect: false },
        { answerText: 'SQL injection', isCorrect: true },
      ],
    explanation: 'The correct answer is: D. SQL injection SQL injection is a type of attack that involves inserting malicious SQL statements into an input field. These statements can then be executed by the database, allowing the attacker to view or manipulate the data. This can lead to unauthorized access to the database, data leakage, or even the modification and deletion of data. Here’s why the other options are not correct in this context: - A. This involves injecting malicious scripts into webpages viewed by other users, but it does not specifically involve running commands that directly view or manipulate data in a database. - B This typically refers to installing applications from unofficial sources, not related to input fields and running commands. -C. This involves exploiting a program by writing more data to a buffer than it can hold, potentially allowing the execution of arbitrary code, but it does not specifically use input fields to run commands on data.'
  },
    {
      questionText: 'Employees in the research and development business unit receive extensive training to ensure they understand how to best protect company data. Which of the following is the type of data these employees are most likely to use in day-to-day work activities?',
      answerOptions: [
        { answerText: 'Encrypted', isCorrect: false },
        { answerText: 'Intellectual property', isCorrect: true },
        { answerText: 'Critical', isCorrect: false },
        { answerText: 'Data in transit', isCorrect: false },
      ],
    explanation: 'B. Intellectual property Employees in R&D are typically involved in creating, developing, and improving products, technologies, or processes. The data they handle often includes sensitive and proprietary information'
  },
    {
      questionText: 'A company has begun labeling all laptops with asset inventory stickers and associating them with employee IDs. Which of the following security benefits do these actions provide? (Choose two.)',
      answerOptions: [
        { answerText: 'If a security incident occurs on the device, the correct employee can be notified.', isCorrect: true },
        { answerText: 'The security team will be able to send user awareness training to the appropriate device.', isCorrect: false },
        { answerText: 'Users can be mapped to their devices when configuring software MFA tokens.', isCorrect: false },
        { answerText: 'User-based firewall policies can be correctly targeted to the appropriate laptops.', isCorrect: false },
        { answerText: 'When conducting penetration testing, the security team will be able to target the desired laptops.', isCorrect: false },
        { answerText: 'Company data can be accounted for when the employee leaves the organization.', isCorrect: true },
      ],
    explanation: 'AC A. If a security incident occurs on the device, the correct employee can be notified. By associating devices with specific employees, the security team can quickly identify and notify the responsible employee in the event of a security incident. This helps in timely incident response and remediation. C. Users can be mapped to their devices when configuring software MFA tokens. Associating devices with employee IDs allows for accurate mapping of users to their devices. This is particularly important when setting up and managing multi-factor authentication (MFA) tokens, ensuring they are configured for the correct devices and users.'
  },
    {
      questionText: 'A technician wants to improve the situational and environmental awareness of existing users as they transition from remote to in-office work. Which of the following is the best option?',
      answerOptions: [
        { answerText: 'Send out periodic security reminders.', isCorrect: false },
        { answerText: 'Update the content of new hire documentation.', isCorrect: false },
        { answerText: 'Modify the content of recurring training.', isCorrect: true },
        { answerText: 'Implement a phishing campaign.', isCorrect: false },
      ],
    explanation: 'C. its the only thing that actually changes. wokring remote you\'d still be able to recieve phishing training.'
  },
    {
      questionText: 'A newly appointed board member with cybersecurity knowledge wants the board of directors to receive a quarterly report detailing the number of incidents that impacted the organization. The systems administrator is creating a way to present the data to the board of directors. Which of the following should the systems administrator use?',
      answerOptions: [
        { answerText: 'Packet captures', isCorrect: false },
        { answerText: 'Vulnerability scans', isCorrect: false },
        { answerText: 'Metadata', isCorrect: false },
        { answerText: 'Dashboard', isCorrect: true },
      ],
    explanation: 'Dashboard: A dashboard is a graphical user interface that provides at-a-glance views of key performance indicators (KPIs) and other important metrics. In the context of cybersecurity, a dashboard can be used to present summarized information about security incidents, including the number of incidents, their severity, affected systems, and trends over time. Dashboards can provide a visually appealing and easy-to-understand way to present quarterly incident reports to the board of directors, making them the most suitable option among the choices provided. Therefore, the systems administrator should use Dashboard to present the quarterly incident reports to the board of directors. A dashboard can effectively summarize incident data and provide a visually appealing presentation format for the board\'s review.'
  },
    {
      questionText: 'A systems administrator receives the following alert from a file integrity monitoring tool:The hash of the cmd.exe file has changed.The systems administrator checks the OS logs and notices that no patches were applied in the last two months. Which of the following most likely occurred?',
      answerOptions: [
        { answerText: 'The end user changed the file permissions.', isCorrect: false },
        { answerText: 'A cryptographic collision was detected.', isCorrect: false },
        { answerText: 'A snapshot of the file system was taken.', isCorrect: false },
        { answerText: 'A rootkit was deployed.', isCorrect: true },
      ],
    explanation: 'D. A rootkit was deployed. A change in the hash of a critical system file like cmd.exe, without any corresponding patches or updates being applied, is a strong indicator of potential malicious activity. A rootkit is a type of malware that can modify system files and hide its presence to maintain persistent and privileged access to a system. If a rootkit has altered cmd.exe, it could be an attempt to replace the legitimate command prompt with a malicious version, or to modify its behavior for nefarious purposes. This is a serious security concern and should be investigated immediately.'
  },
    {
      questionText: 'Which of the following roles, according to the shared responsibility model, is responsible for securing the company’s database in an IaaS model for a cloud environment?',
      answerOptions: [
        { answerText: 'Client', isCorrect: true },
        { answerText: 'Third-party vendor', isCorrect: false },
        { answerText: 'Cloud provider', isCorrect: false },
        { answerText: 'DBA', isCorrect: false },
      ],
    explanation: 'Client: In the shared responsibility model, the client, or cloud customer, is responsible for securing their data and applications running on the cloud infrastructure. This includes configuring security settings, implementing access controls, and managing user permissions for their resources. However, the specific responsibility for securing the company\'s database in an Infrastructure as a Service (IaaS) model depends on the division of responsibilities outlined in the model. Given the options provided and the context of the shared responsibility model for a cloud environment, the most appropriate role responsible for securing the company\'s database in an IaaS model would be Client. The client is typically responsible for securing their data and applications, including databases, within the cloud infrastructure. However, the DBA would also play a significant role in implementing database security measures within the IaaS environment, working in collaboration with the client\'s security team.'
  },
    {
      questionText: 'A client asked a security company to provide a document outlining the project, the cost, and the completion time frame. Which of the following documents should the company provide to the client?',
      answerOptions: [
        { answerText: 'MSA', isCorrect: false },
        { answerText: 'SLA', isCorrect: false },
        { answerText: 'BPA', isCorrect: false },
        { answerText: 'SOW', isCorrect: true },
      ],
    explanation: 'The company should provide the client with a Statement of Work (SOW). A Statement of Work is a document that outlines the details of a project, including the scope, deliverables, timeline, and cost. It is used to ensure that both the client and the service provider have a clear understanding of the project\'s requirements and expectations. - MSA (Master Service Agreement) An overarching contract that defines the terms and conditions under which services will be provided. - SLA (Service Level Agreement) A contract that defines the level of service expected from the service provider. - BPA (Business Partnership Agreement) An agreement that defines the relationship and responsibilities between business partners. Therefore, the correct answer is: D. SOW'
  },
    {
      questionText: 'A security team is reviewing the findings in a report that was delivered after a third party performed a penetration test. One of the findings indicated that a web application form field is vulnerable to cross-site scripting. Which of the following application security techniques should the security analyst recommend the developer implement to prevent this vulnerability?',
      answerOptions: [
        { answerText: 'Secure cookies', isCorrect: false },
        { answerText: 'Version control', isCorrect: false },
        { answerText: 'Input validation', isCorrect: true },
        { answerText: 'Code signing', isCorrect: false },
      ],
    explanation: 'Answer is C. Its important to make sure that javascript code can not be inputted and executed into Form fields.'
  },
    {
      questionText: 'Which of the following must be considered when designing a high-availability network? (Choose two).',
      answerOptions: [
        { answerText: 'Ease of recovery', isCorrect: true },
        { answerText: 'Ability to patch', isCorrect: false },
        { answerText: 'Physical isolation', isCorrect: false },
        { answerText: 'Responsiveness', isCorrect: true },
        { answerText: 'Attack surface', isCorrect: false },
        { answerText: 'Extensible authentication', isCorrect: false },
      ],
    explanation: 'When designing a high-availability network, two key considerations are: A. Ease of recovery D. Responsiveness - Ease of recovery. This is essential for high availability because the network must be able to recover quickly from failures to minimize downtime. - Responsiveness. Ensuring that the network can handle high traffic loads and respond quickly to user requests is crucial for maintaining high availability. Other factors like physical isolation, ability to patch, attack surface, and extensible authentication are important for security and maintenance but are not primary considerations for high availability. Therefore, the correct answers are: A. Ease of recovery D. Responsiveness'
  },
    {
      questionText: 'A technician needs to apply a high-priority patch to a production system. Which of the following steps should be taken first?',
      answerOptions: [
        { answerText: 'Air gap the system.', isCorrect: false },
        { answerText: 'Move the system to a different network segment.', isCorrect: false },
        { answerText: 'Create a change control request.', isCorrect: true },
        { answerText: 'Apply the patch to the system.', isCorrect: false },
      ],
    explanation: 'Change Control is the process that management uses to identify, document and authorize changes to an IT environment. It minimizes the likelihood of disruptions, unauthorized alterations and errors. The change control procedures should be designed with the size and complexity of the environment in mind.'
  },
    {
      questionText: 'Which of the following describes the reason root cause analysis should be conducted as part of incident response?',
      answerOptions: [
        { answerText: 'To gather IoCs for the investigation', isCorrect: false },
        { answerText: 'To discover which systems have been affected', isCorrect: false },
        { answerText: 'To eradicate any trace of malware on the network', isCorrect: false },
        { answerText: 'To prevent future incidents of the same nature', isCorrect: true },
      ],
    explanation: 'To prevent future incidents of the same nature'
  },
    {
      questionText: 'Which of the following is the most likely outcome if a large bank fails an internal PCI DSS compliance assessment?',
      answerOptions: [
        { answerText: 'Fines', isCorrect: false },
        { answerText: 'Audit findings', isCorrect: true },
        { answerText: 'Sanctions', isCorrect: false },
        { answerText: 'Reputation damage', isCorrect: false },
      ],
    explanation: 'B. Audit findings While fines, sanctions, and reputation damage can be potential consequences of failing to meet PCI DSS compliance, the most immediate and likely outcome of failing an internal PCI DSS compliance assessment is the generation of audit findings. These findings will detail the areas of non-compliance and typically result in the organization needing to take corrective actions to address the identified issues. If the findings are not addressed, this could lead to further consequences such as fines, sanctions, or reputation damage. Therefore, the correct answer is: B. Audit findings'
  },
    {
      questionText: 'A company is developing a business continuity strategy and needs to determine how many staff members would be required to sustain the business in the case of a disruption. Which of the following best describes this step?',
      answerOptions: [
        { answerText: 'Capacity planning', isCorrect: true },
        { answerText: 'Redundancy', isCorrect: false },
        { answerText: 'Geographic dispersion', isCorrect: false },
        { answerText: 'Tabletop exercise', isCorrect: false },
      ],
    explanation: 'A. Capacity planning Explanation: Capacity planning involves determining the staffing levels needed to sustain business operations during a disruption. This ensures that the organization has sufficient human resources to maintain essential functions and minimize downtime.'
  },
    {
      questionText: 'A company’s legal department drafted sensitive documents in a SaaS application and wants to ensure the documents cannot be accessed by individuals in high-risk countries. Which of the following is the most effective way to limit this access?',
      answerOptions: [
        { answerText: 'Data masking', isCorrect: false },
        { answerText: 'Encryption', isCorrect: false },
        { answerText: 'Geolocation policy', isCorrect: true },
        { answerText: 'Data sovereignty regulation', isCorrect: false },
      ],
    explanation: 'What is Geolocation Protection? Organizations may implement access control policies that restrict or allow access to certain resources based on the geographic location of users or devices. For example, they might limit access to sensitive systems only to users connecting from specific geographic regions or countries.'
  },
    {
      questionText: 'Which of the following is a hardware-specific vulnerability?',
      answerOptions: [
        { answerText: 'Firmware version', isCorrect: true },
        { answerText: 'Buffer overflow', isCorrect: false },
        { answerText: 'SQL injection', isCorrect: false },
        { answerText: 'Cross-site scripting', isCorrect: false },
      ],
    explanation: 'Vulnerabilities in firmware are specific to the hardware they control, as different hardware may have different firmware versions with unique vulnerabilities. For example, an outdated firmware version might have security flaws that can be exploited, affecting the hardware\'s security posture. Firmware vulnerabilities are intrinsically tied to the hardware on which they run, making them hardware-specific. An outdated or improperly secured firmware version can introduce vulnerabilities unique to that hardware platform.'
  },
    {
      questionText: 'While troubleshooting a firewall configuration, a technician determines that a “deny any” policy should be added to the bottom of the ACL. The technician updates the policy, but the new policy causes several company servers to become unreachable.Which of the following actions would prevent this issue?',
      answerOptions: [
        { answerText: 'Documenting the new policy in a change request and submitting the request to change management', isCorrect: false },
        { answerText: 'Testing the policy in a non-production environment before enabling the policy in the production network', isCorrect: true },
        { answerText: 'Disabling any intrusion prevention signatures on the “deny any” policy prior to enabling the new policy', isCorrect: false },
        { answerText: 'Including an “allow any” policy above the “deny any” policy', isCorrect: false },
      ],
    explanation: 'Frankly it should be both A and B. Submitting it to change management does not prevent the issue if it isn\'t caught by change management, and testing it in non-prod would but also shouldn\'t be done without a request to change management. It\'s a different question than the previous one regarding change management: Yes the technician SHOULD put in a change management request first, but that\'s not the question, the question is what would prevent it and the change management request does not prevent an issue, rather it lets everyone know what is happening and provides a backout plan if issues come up. That still does not PREVENT the issue though so /shrug'
  },
    {
      questionText: 'An organization is building a new backup data center with cost-benefit as the primary requirement and RTO and RPO values around two days. Which of the following types of sites is the best for this scenario?',
      answerOptions: [
        { answerText: 'Real-time recovery', isCorrect: false },
        { answerText: 'Hot', isCorrect: false },
        { answerText: 'Cold', isCorrect: false },
        { answerText: 'Warm', isCorrect: true },
      ],
    explanation: 'Warm Sites ● Not fully equipped, but fundamentals in place ● Can be up and running within a few days ● Cheaper than hot sites but with a slight delay Cold Sites ● Fewer facilities than warm sites ● May be just an empty building, ready in 1-2 months ● Cost-effective but adds more recovery time'
  },
    {
      questionText: 'A company requires hard drives to be securely wiped before sending decommissioned systems to recycling. Which of the following best describes this policy?',
      answerOptions: [
        { answerText: 'Enumeration', isCorrect: false },
        { answerText: 'Sanitization', isCorrect: true },
        { answerText: 'Destruction', isCorrect: false },
        { answerText: 'Inventory', isCorrect: false },
      ],
    explanation: 'securely wiped ... clorox wipes.... clorox wipes clean and sanitize... B Sanitization'
  },
    {
      questionText: 'A systems administrator works for a local hospital and needs to ensure patient data is protected and secure. Which of the following data classifications should be used to secure patient data?',
      answerOptions: [
        { answerText: 'Private', isCorrect: false },
        { answerText: 'Critical', isCorrect: false },
        { answerText: 'Sensitive', isCorrect: true },
        { answerText: 'Public', isCorrect: false },
      ],
    explanation: 'C. Sensitive Sensitive - Intellectual property, PII, PHI • Confidential - Very sensitive, must be approved to view • Public / Unclassified - No restrictions on viewing the data • Private / Classified / Restricted – Restricted access, may require an NDA • Critical - Data should always be available'
  },
    {
      questionText: 'A U.S.-based cloud-hosting provider wants to expand its data centers to new international locations. Which of the following should the hosting provider consider first?',
      answerOptions: [
        { answerText: 'Local data protection regulations', isCorrect: true },
        { answerText: 'Risks from hackers residing in other countries', isCorrect: false },
        { answerText: 'Impacts to existing contractual obligations', isCorrect: false },
        { answerText: 'Time zone differences in log correlation', isCorrect: false },
      ],
    explanation: 'A. Local data protection regulations Laws may prohibit where data is stored – GDPR (General Data Protection Regulation) – Data collected on EU citizens must be stored in the EU'
  },
    {
      questionText: 'Which of the following would be the best way to block unknown programs from executing?',
      answerOptions: [
        { answerText: 'Access control list', isCorrect: false },
        { answerText: 'Application allow list', isCorrect: true },
        { answerText: 'Host-based firewall', isCorrect: false },
        { answerText: 'DLP solution', isCorrect: false },
      ],
    explanation: 'Application allow list only allows trusted applications or files to run'
  },
    {
      questionText: 'A company hired a consultant to perform an offensive security assessment covering penetration testing and social engineering.Which of the following teams will conduct this assessment activity?',
      answerOptions: [
        { answerText: 'White', isCorrect: false },
        { answerText: 'Purple', isCorrect: false },
        { answerText: 'Blue', isCorrect: false },
        { answerText: 'Red', isCorrect: true },
      ],
    explanation: 'D because red teams are offensive and blue teams are defensive'
  },
    {
      questionText: 'A software development manager wants to ensure the authenticity of the code created by the company. Which of the following options is the most appropriate?',
      answerOptions: [
        { answerText: 'Testing input validation on the user input fields', isCorrect: false },
        { answerText: 'Performing code signing on company-developed software', isCorrect: true },
        { answerText: 'Performing static code analysis on the software', isCorrect: false },
        { answerText: 'Ensuring secure cookies are use', isCorrect: false },
      ],
    explanation: 'Code signing involves applying a digital signature to software, verifying the identity of the developer and ensuring that the code has not been altered or tampered with since it was signed. This process provides assurance of the authenticity and integrity of the software. Testing input validation, performing static code analysis, and ensuring secure cookies are important security practices but do not specifically address the need to verify the authenticity of the code.'
  },
    {
      questionText: 'Which of the following can be used to identify potential attacker activities without affecting production servers?',
      answerOptions: [
        { answerText: 'Honeypot', isCorrect: true },
        { answerText: 'Video surveillance', isCorrect: false },
        { answerText: 'Zero Trust', isCorrect: false },
        { answerText: 'Geofencing', isCorrect: false },
      ],
    explanation: 'Honeypot - a network-attached system set up as a decoy to lure cyber attackers and detect, deflect and study hacking attempts on systems.'
  },
    {
      questionText: 'During an investigation, an incident response team attempts to understand the source of an incident. Which of the following incident response activities describes this process?',
      answerOptions: [
        { answerText: 'Analysis', isCorrect: true },
        { answerText: 'Lessons learned', isCorrect: false },
        { answerText: 'Detection', isCorrect: false },
        { answerText: 'Containment', isCorrect: false },
      ],
    explanation: 'Answer is A because you need to conduct an analysis to find out what the source of the incident was.'
  },
    {
      questionText: 'A security practitioner completes a vulnerability assessment on a company’s network and finds several vulnerabilities, which the operations team remediates. Which of the following should be done next?',
      answerOptions: [
        { answerText: 'Conduct an audit.', isCorrect: false },
        { answerText: 'Initiate a penetration test.', isCorrect: false },
        { answerText: 'Rescan the network.', isCorrect: true },
        { answerText: 'Submit a report.', isCorrect: false },
      ],
    explanation: 'Rescanning the network is essential to verify that the previously identified vulnerabilities have been successfully remediated and to ensure that no new vulnerabilities have been introduced. This step confirms the effectiveness of the remediation efforts before moving on to further actions such as audits, penetration tests, or reporting.'
  },
    {
      questionText: 'An administrator was notified that a user logged in remotely after hours and copied large amounts of data to a personal device.Which of the following best describes the user’s activity?',
      answerOptions: [
        { answerText: 'Penetration testing', isCorrect: false },
        { answerText: 'Phishing campaign', isCorrect: false },
        { answerText: 'External audit', isCorrect: false },
        { answerText: 'Insider threat', isCorrect: true },
      ],
    explanation: 'D. Insider Threat An insider threat is the potential for an insider to use their authorized access or understanding of an organization to harm that organization.'
  },
    {
      questionText: 'Which of the following allows for the attribution of messages to individuals?',
      answerOptions: [
        { answerText: 'Adaptive identity', isCorrect: false },
        { answerText: 'Non-repudiation', isCorrect: true },
        { answerText: 'Authentication', isCorrect: false },
        { answerText: 'Access logs', isCorrect: false },
      ],
    explanation: 'I can\'t understand the sentence. Bad question'
  },
    {
      questionText: 'Which of the following is the best way to consistently determine on a daily basis whether security settings on servers have been modified?',
      answerOptions: [
        { answerText: 'Automation', isCorrect: true },
        { answerText: 'Compliance checklist', isCorrect: false },
        { answerText: 'Attestation', isCorrect: false },
        { answerText: 'Manual audit', isCorrect: false },
      ],
    explanation: 'Automation involves using tools and scripts to regularly check and report on the security settings of servers. This method ensures consistent, real-time monitoring and can quickly detect any unauthorized changes. It is more reliable and efficient compared to manual methods, compliance checklists, or periodic attestations, which may not capture changes as promptly or consistently.'
  },
    {
      questionText: 'Which of the following tools can assist with detecting an employee who has accidentally emailed a file containing a customer’s PII?',
      answerOptions: [
        { answerText: 'SCAP', isCorrect: false },
        { answerText: 'NetFlow', isCorrect: false },
        { answerText: 'Antivirus', isCorrect: false },
        { answerText: 'DLP', isCorrect: true },
      ],
    explanation: 'Data Loss Prevention protects sensitive information from loss, corruption, misuse, or unauthorized access.'
  },
    {
      questionText: 'An organization recently updated its security policy to include the following statement:Regular expressions are included in source code to remove special characters such as $, |, ;. &, `, and ? from variables set by forms in a web application.Which of the following best explains the security technique the organization adopted by making this addition to the policy?',
      answerOptions: [
        { answerText: 'Identify embedded keys', isCorrect: false },
        { answerText: 'Code debugging', isCorrect: false },
        { answerText: 'Input validation', isCorrect: true },
        { answerText: 'Static code analysis', isCorrect: false },
      ],
    explanation: 'Input validation is the process of analyzing inputs and disallowing those which are considered unsuitable. Ie: Only allowing accepted inputs based on specific criteria'
  },
    {
      questionText: 'A security analyst and the management team are reviewing the organizational performance of a recent phishing campaign. The user click-through rate exceeded the acceptable risk threshold, and the management team wants to reduce the impact when a user clicks on a link in a phishing message. Which of the following should the analyst do?',
      answerOptions: [
        { answerText: 'Place posters around the office to raise awareness of common phishing activities.', isCorrect: false },
        { answerText: 'Implement email security filters to prevent phishing emails from being delivered.', isCorrect: false },
        { answerText: 'Update the EDR policies to block automatic execution of downloaded programs.', isCorrect: true },
        { answerText: 'Create additional training for users to recognize the signs of phishing attempts.', isCorrect: false },
      ],
    explanation: 'Updating the Endpoint Detection and Response (EDR) policies to block the automatic execution of downloaded programs helps to mitigate the risk by preventing malicious software from running even if a user clicks on a phishing link. This technical control directly addresses the potential consequences of a phishing attack by stopping harmful actions from taking place after the initial click, thus reducing the overall impact of the phishing campaign. While raising awareness (option A), implementing email security filters (option B), and creating additional training (option D) are all valuable preventive measures, they do not directly reduce the impact after a phishing link is clicked.'
  },
    {
      questionText: 'Which of the following has been implemented when a host-based firewall on a legacy Linux system allows connections from only specific internal IP addresses?',
      answerOptions: [
        { answerText: 'Compensating control', isCorrect: true },
        { answerText: 'Network segmentation', isCorrect: false },
        { answerText: 'Transfer of risk', isCorrect: false },
        { answerText: 'SNMP traps', isCorrect: false },
      ],
    explanation: 'A. Compensating control w, the keyword in the question is "legacy". Suppose that you have a legacy Linux server which is not compatible with those network-based firewalls, routers and multi-layer switches which is preventing you not just from building VLANs (Network Segmentation), but also from applying white-listing ACL technique against malicious IP addresses. So, what you\'re going to do is you are going to use host-based firewalls as a compensation for network appliances to be able to accomplish the similar end-result'
  },
    {
      questionText: 'The management team notices that new accounts that are set up manually do not always have correct access or permissions.Which of the following automation techniques should a systems administrator use to streamline account creation?',
      answerOptions: [
        { answerText: 'Guard rail script', isCorrect: false },
        { answerText: 'Ticketing workflow', isCorrect: false },
        { answerText: 'Escalation script', isCorrect: false },
        { answerText: 'User provisioning script', isCorrect: true },
      ],
    explanation: 'D. User provisioning script A user provisioning script automates the process of creating user accounts, ensuring that each new account is set up with the correct access and permissions consistently. This helps prevent errors that can occur with manual account creation. Therefore, the correct answer is: D. User provisioning script'
  },
    {
      questionText: 'A company is planning to set up a SIEM system and assign an analyst to review the logs on a weekly basis. Which of the following types of controls is the company setting up?',
      answerOptions: [
        { answerText: 'Corrective', isCorrect: false },
        { answerText: 'Preventive', isCorrect: false },
        { answerText: 'Detective', isCorrect: true },
        { answerText: 'Deterrent', isCorrect: false },
      ],
    explanation: 'C. Detective By setting up a Security Information and Event Management (SIEM) system and assigning an analyst to review the logs on a weekly basis, the company is implementing a detective control. Detective controls are designed to identify and alert on potential security incidents, allowing the organization to take appropriate action after an event has occurred. Therefore, the correct answer is: C. Detective'
  },
    {
      questionText: 'A systems administrator is looking for a low-cost application-hosting solution that is cloud-based. Which of the following meets these requirements?',
      answerOptions: [
        { answerText: 'Serverless framework', isCorrect: true },
        { answerText: 'Type 1 hypervisor', isCorrect: false },
        { answerText: 'SD-WAN', isCorrect: false },
        { answerText: 'SDN', isCorrect: false },
      ],
    explanation: 'A. Serverless framework A serverless framework is a cloud-based application-hosting solution that allows developers to build and run applications without managing the underlying infrastructure. It is typically a low-cost option because it charges based on the actual usage of the resources rather than requiring the provisioning of dedicated servers. Therefore, the correct answer is: A. Serverless framework'
  },
    {
      questionText: 'A security operations center determines that the malicious activity detected on a server is normal. Which of the following activities describes the act of ignoring detected activity in the future?',
      answerOptions: [
        { answerText: 'Tuning', isCorrect: true },
        { answerText: 'Aggregating', isCorrect: false },
        { answerText: 'Quarantining', isCorrect: false },
        { answerText: 'Archiving', isCorrect: false },
      ],
    explanation: 'The act of ignoring detected activity in the future is described as A. Tuning. Tuning refers to the process of adjusting the configuration of a system, in this case, the security operations center’s detection systems, to reduce or eliminate the number of false positives. In this context, if the so-called “malicious activity” is determined to be normal and is expected to recur, the system can be tuned to ignore this activity in the future, preventing unnecessary alerts. Please note that while the other options (B. Aggregating, C. Quarantining, D. Archiving) are activities related to managing and responding to security events, they do not specifically apply to the scenario of ignoring detected activity in the future.'
  },
    {
      questionText: 'A security analyst reviews domain activity logs and notices a large number of failed login attempts for a single user account, jsmith. Which of the following is the best explanation for what the security analyst has discovered?',
      answerOptions: [
        { answerText: 'The user jsmith’s account has been locked out.', isCorrect: false },
        { answerText: 'A keylogger is installed on jsmith’s workstation.', isCorrect: false },
        { answerText: 'An attacker is attempting to brute force jsmith’s account.', isCorrect: true },
        { answerText: 'Ransomware has been deployed in the domain.', isCorrect: false },
      ],
    explanation: 'The scenario perfectly matches a common security issue where attackers gain partial access through stolen credentials but are thwarted by MFA, which they try to bypass unsuccessfully.The repeated success in password authentication suggests that the attacker has access to jsmiths password, but the failure of MFA points to an attempt to guess or brute-force the MFA code.'
  },
    {
      questionText: 'A company is concerned about weather events causing damage to the server room and downtime. Which of the following should the company consider?',
      answerOptions: [
        { answerText: 'Clustering servers', isCorrect: false },
        { answerText: 'Geographic dispersion', isCorrect: true },
        { answerText: 'Load balancers', isCorrect: false },
        { answerText: 'Off-site backups', isCorrect: false },
      ],
    explanation: 'Given the concern about weather events causing damage to the server room and resulting downtime, the company should consider measures that protect against physical damage and ensure business continuity. The most relevant option for this scenario is: B. Geographic dispersion Geographic dispersion involves placing critical infrastructure in multiple, geographically distant locations. This strategy ensures that even if one site is affected by a weather event, operations can continue at another site, minimizing downtime and maintaining availability.'
  },
    {
      questionText: 'Which of the following is a primary security concern for a company setting up a BYOD program?',
      answerOptions: [
        { answerText: 'End of life', isCorrect: false },
        { answerText: 'Buffer overflow', isCorrect: false },
        { answerText: 'VM escape', isCorrect: false },
        { answerText: 'Jailbreaking', isCorrect: true },
      ],
    explanation: 'When setting up a Bring Your Own Device (BYOD) program, the primary security concern is ensuring that personal devices, which may not be under the company\'s direct control, do not introduce security risks into the organization. Among the options provided, the most relevant concern is: D. Jailbreaking Jailbreaking refers to removing the manufacturer\'s restrictions on a device, which can compromise the security of the device. This makes it more susceptible to malware and unauthorized access, posing a significant risk to the company\'s network and data when such a device is connected.'
  },
    {
      questionText: 'A company decided to reduce the cost of its annual cyber insurance policy by removing the coverage for ransomware attacks.Which of the following analysis elements did the company most likely use in making this decision?',
      answerOptions: [
        { answerText: 'MTTR', isCorrect: false },
        { answerText: 'RTO', isCorrect: false },
        { answerText: 'ARO', isCorrect: true },
        { answerText: 'MTBF', isCorrect: false },
      ],
    explanation: 'MTTR= mean time to repair RTO=recovery time objective ARO= annualized rate of occurance MTBF= mean time between failures. ARO is it'
  },
    {
      questionText: 'Which of the following is the most likely to be included as an element of communication in a security awareness program?',
      answerOptions: [
        { answerText: 'Reporting phishing attempts or other suspicious activities', isCorrect: true },
        { answerText: 'Detecting insider threats using anomalous behavior recognition', isCorrect: false },
        { answerText: 'Verifying information when modifying wire transfer data', isCorrect: false },
        { answerText: 'Performing social engineering as part of third-party penetration testing', isCorrect: false },
      ],
    explanation: 'Easiest way to think of this question is this security awareness program is likely to be made company wide for the avg employee with no computer skills. B C D are all for the cybersecurity team specifically'
  },
    {
      questionText: 'Which of the following is the phase in the incident response process when a security analyst reviews roles and responsibilities?',
      answerOptions: [
        { answerText: 'Preparation', isCorrect: true },
        { answerText: 'Recovery', isCorrect: false },
        { answerText: 'Lessons learned', isCorrect: false },
        { answerText: 'Analysis', isCorrect: false },
      ],
    explanation: 'A. Preparation The preparation phase in the incident response process is when a security analyst reviews roles and responsibilities. This phase involves planning and setting up the necessary tools, processes, and team structures to effectively respond to potential security incidents. Therefore, the correct answer is: A. Preparation'
  },
    {
      questionText: 'After a recent vulnerability scan, a security engineer needs to harden the routers within the corporate network. Which of the following is the most appropriate to disable?',
      answerOptions: [
        { answerText: 'Console access', isCorrect: false },
        { answerText: 'Routing protocols', isCorrect: false },
        { answerText: 'VLANs', isCorrect: false },
        { answerText: 'Web-based administration', isCorrect: true },
      ],
    explanation: 'The most appropriate option to disable to harden the routers would be: D. Web-based administration Web-based administration, also known as remote management or HTTP/HTTPS access, is a common feature in routers that allows administrators to manage the device remotely using a web browser. However, this feature also introduces a potential vulnerability, as it opens up the router to potential web-based attacks. Disabling web-based administration would reduce the attack surface and prevent potential exploits, making the router more secure. Console access (A) is necessary for local management, routing protocols (B) are essential for network operation, and VLANs (C) are used for network segmentation and security. Disabling web-based administration (D) is the most appropriate option to harden the router.'
  },
    {
      questionText: 'A security administrator needs a method to secure data in an environment that includes some form of checks so track any changes. Which of the following should the administrator set up to achieve this goal?',
      answerOptions: [
        { answerText: 'SPF', isCorrect: false },
        { answerText: 'GPO', isCorrect: false },
        { answerText: 'NAC', isCorrect: false },
        { answerText: 'FIM', isCorrect: true },
      ],
    explanation: 'D. FIM (File Integrity Monitoring) File Integrity Monitoring (FIM) is a security technology that monitors and detects changes in files. FIM solutions can track modifications, access, or deletions of files and notify administrators of any changes, thus ensuring data integrity and security. Therefore, the correct answer is: D. FIM'
  },
    {
      questionText: 'An administrator is reviewing a single server\'s security logs and discovers a user session escalating privileges to root. Which of the following best describes the action captured in this log file?',
      answerOptions: [
        { answerText: 'Brute-force attack', isCorrect: true },
        { answerText: 'Privilege escalation', isCorrect: false },
        { answerText: 'Failed password audit', isCorrect: false },
        { answerText: 'Forgotten password by the user', isCorrect: false },
      ],
    explanation: 'Event ID 4625 is logged for any logon failure. It generates on the computer where logon attempt was made.In this scenario we can see multiple login attempts every few seconds indicating that this is a potential brute-force attack.'
  },
    {
      questionText: 'A security engineer is implementing FDE for all laptops in an organization. Which of the following are the most important for the engineer to consider as part of the planning process? (Choose two.)',
      answerOptions: [
        { answerText: 'Key escrow', isCorrect: true },
        { answerText: 'TPM presence', isCorrect: true },
        { answerText: 'Digital signatures', isCorrect: false },
        { answerText: 'Data tokenization', isCorrect: false },
        { answerText: 'Public key management', isCorrect: false },
        { answerText: 'Certificate authority linking', isCorrect: false },
      ],
    explanation: 'A. Key escrow B. TPM presence - **Key escrow:** This is important to ensure that encryption keys can be recovered in case they are lost or forgotten. It is a crucial consideration for Full Disk Encryption (FDE) to maintain access to data even if issues arise with the primary encryption keys. - **TPM presence:** Trusted Platform Module (TPM) is a hardware-based security feature that can store encryption keys securely. Ensuring the presence of TPM on laptops enhances the security of FDE by protecting the encryption keys from being accessed or tampered with. Therefore, the most important considerations for the security engineer are: A. Key escrow B. TPM presence'
  },
    {
      questionText: 'A security analyst scans a company\'s public network and discovers a host is running a remote desktop that can be used to access the production network. Which of the following changes should the security analyst recommend?',
      answerOptions: [
        { answerText: 'Changing the remote desktop port to a non-standard number', isCorrect: false },
        { answerText: 'Setting up a VPN and placing the jump server inside the firewall', isCorrect: true },
        { answerText: 'Using a proxy for web connections from the remote desktop server', isCorrect: false },
        { answerText: 'Connecting the remote server to the domain and increasing the password length', isCorrect: false },
      ],
    explanation: 'Setting up a VPN and placing the jump server inside the firewall is the most secure approach because it reduces the attack surface and ensures that only authorized users can access the remote desktop service. This solution addresses the primary security concern of protecting sensitive production systems by ensuring that only verified users can gain access, thus minimizing the attack surface and potential vulnerabilities.'
  },
    {
      questionText: 'An enterprise has been experiencing attacks focused on exploiting vulnerabilities in older browser versions with well-known exploits. Which of the following security solutions should be configured to best provide the ability to monitor and block these known signature-based attacks?',
      answerOptions: [
        { answerText: 'ACL', isCorrect: false },
        { answerText: 'DLP', isCorrect: false },
        { answerText: 'IDS', isCorrect: false },
        { answerText: 'IPS', isCorrect: true },
      ],
    explanation: 'An IPS is designed to continuously monitor network traffic and take immediate action to block potential threats based on known signatures. It’s an active security measure that not only detects but also prevents the exploitation of known vulnerabilities. A. ACL (Access Control List): ACLs are used to control the flow of traffic based on rules, but they are not dynamic enough to monitor or block signature-based attacks effectively. B. DLP (Data Loss Prevention): DLP systems are focused on preventing data breaches by detecting and blocking potential data leaks/exfiltration, not on monitoring or blocking attacks per se. C. IDS (Intrusion Detection System): While an IDS can detect known signature-based attacks, it does not block them; it only alerts the system administrators of the potential threat. D. IPS (Intrusion Prevention System): As mentioned, an IPS actively monitors and blocks attacks, making it the most suitable option for the scenario described.'
  },
    {
      questionText: 'Security controls in a data center are being reviewed to ensure data is properly protected and that human life considerations are included. Which of the following best describes how the controls should be set up?',
      answerOptions: [
        { answerText: 'Remote access points should fail closed.', isCorrect: false },
        { answerText: 'Logging controls should fail open.', isCorrect: false },
        { answerText: 'Safety controls should fail open.', isCorrect: true },
        { answerText: 'Logical security controls should fail closed.', isCorrect: false },
      ],
    explanation: 'Safety controls failing open is a critical design principle that ensures human life is prioritized in the event of a failure. This principle applies to situations where failing open provides an immediate safety benefit, such as allowing exit doors to unlock automatically during a fire.'
  },
    {
      questionText: 'Which of the following would be best suited for constantly changing environments?',
      answerOptions: [
        { answerText: 'RTOS', isCorrect: false },
        { answerText: 'Containers', isCorrect: true },
        { answerText: 'Embedded systems', isCorrect: false },
        { answerText: 'SCADA', isCorrect: false },
      ],
    explanation: 'lacking context'
  },
    {
      questionText: 'Which of the following incident response activities ensures evidence is properly handled?',
      answerOptions: [
        { answerText: 'E-discovery', isCorrect: false },
        { answerText: 'Chain of custody', isCorrect: true },
        { answerText: 'Legal hold', isCorrect: false },
        { answerText: 'Preservation', isCorrect: false },
      ],
    explanation: 'In this scenario, choice B is correct . Chain of custody is the correct answer because it is specifically designed to ensure that evidence is properly handled, tracked, and documented throughout the incident response process. This approach ensures the integrity and admissibility of evidence in legal settings by maintaining a clear and reliable record of its handling.'
  },
    {
      questionText: 'An accounting clerk sent money to an attacker\'s bank account after receiving fraudulent instructions to use a new account. Which of the following would most likely prevent this activity in the future?',
      answerOptions: [
        { answerText: 'Standardizing security incident reporting', isCorrect: false },
        { answerText: 'Executing regular phishing campaigns', isCorrect: false },
        { answerText: 'Implementing insider threat detection measures', isCorrect: false },
        { answerText: 'Updating processes for sending wire transfers', isCorrect: true },
      ],
    explanation: 'Updating the processes for sending wire transfers would most likely prevent this type of activity in the future. This could include implementing additional verification steps, such as requiring multiple levels of approval, verifying new payment instructions through a separate communication channel, or implementing a callback procedure to confirm the authenticity of the instructions.'
  },
    {
      questionText: 'A systems administrator is creating a script that would save time and prevent human error when performing account creation for a large number of end users. Which of the following would be a good use case for this task?',
      answerOptions: [
        { answerText: 'Off-the-shelf software', isCorrect: false },
        { answerText: 'Orchestration', isCorrect: true },
        { answerText: 'Baseline', isCorrect: false },
        { answerText: 'Policy enforcement', isCorrect: false },
      ],
    explanation: 'A makes no sense B orchestration and automation are treated as the same in the exam objectives so not sure on this one C establishing a baseline (confused on this one) a baseline for what? if it means a baseline for account creation then yes, if it means a baseline like a policy then no.. D policy enforcement.. idk if you\'d need to write a script for that as much as you\'d rely on software.. going with B since the first part of the question doesnt mention automation/orchestration even though the question is very poorly worded.'
  },
    {
      questionText: 'A company\'s marketing department collects, modifies, and stores sensitive customer data. The infrastructure team is responsible for securing the data while in transit and at rest. Which of the following data roles describes the customer?',
      answerOptions: [
        { answerText: 'Processor', isCorrect: false },
        { answerText: 'Custodian', isCorrect: false },
        { answerText: 'Subject', isCorrect: true },
        { answerText: 'Owner', isCorrect: false },
      ],
    explanation: 'In the context of data roles, the customer whose sensitive data is being collected, modified, and stored is referred to as the "Subject." The data subject is the individual to whom the data pertains.'
  },
    {
      questionText: 'Which of the following describes the maximum allowance of accepted risk?',
      answerOptions: [
        { answerText: 'Risk indicator', isCorrect: false },
        { answerText: 'Risk level', isCorrect: false },
        { answerText: 'Risk score', isCorrect: false },
        { answerText: 'Risk threshold', isCorrect: true },
      ],
    explanation: 'This refers to the point or level of risk that an organization is willing to tolerate. Beyond this threshold, actions must be taken to mitigate or reduce the risk to an acceptable level. It defines the boundary between acceptable and unacceptable risk. -The risk threshold is essentially the upper limit of risk that is deemed acceptable by an organization. It serves as a guideline for decision-making regarding risk management and response strategies. -Organizations set risk thresholds based on their risk appetite and tolerance, helping them determine when to take action and allocate resources for risk mitigation.'
  },
    {
      questionText: 'A security analyst receives alerts about an internal system sending a large amount of unusual DNS queries to systems on the internet over short periods of time during non-business hours. Which of the following is most likely occurring?',
      answerOptions: [
        { answerText: 'A worm is propagating across the network.', isCorrect: false },
        { answerText: 'Data is being exfiltrated.', isCorrect: true },
        { answerText: 'A logic bomb is deleting data.', isCorrect: false },
        { answerText: 'Ransomware is encrypting files.', isCorrect: false },
      ],
    explanation: 'The scenario describes an internal system sending unusual and large amounts of DNS queries to external systems, especially during non-business hours. This behavior is indicative of data exfiltration, where an attacker tries to move data out of the network covertly.'
  },
    {
      questionText: 'A technician is opening ports on a firewall for a new system being deployed and supported by a SaaS provider. Which of the following is a risk in the new system?',
      answerOptions: [
        { answerText: 'Default credentials', isCorrect: false },
        { answerText: 'Non-segmented network', isCorrect: false },
        { answerText: 'Supply chain vendor', isCorrect: true },
        { answerText: 'Vulnerable software', isCorrect: false },
      ],
    explanation: 'B. Non-segmented network Opening ports on a firewall for a new system introduces the risk that the new system might be deployed on a non-segmented network. This means that the new system and its traffic could potentially be exposed to other parts of the network, increasing the risk of lateral movement by an attacker if the system is compromised. Network segmentation helps in containing potential breaches and limiting access to sensitive areas of the network. Therefore, the correct answer is: B. Non-segmented network'
  },
    {
      questionText: 'A systems administrator is working on a solution with the following requirements:\n\n• Provide a secure zone.\n• Enforce a company-wide access control policy.\n• Reduce the scope of threats.\n\nWhich of the following is the systems administrator setting up?',
      answerOptions: [
        { answerText: 'Zero Trust', isCorrect: true },
        { answerText: 'AAA', isCorrect: false },
        { answerText: 'Non-repudiation', isCorrect: false },
        { answerText: 'CIA', isCorrect: false },
      ],
    explanation: 'Zero Trust is a security framework that aligns perfectly with the given requirements. It emphasizes strict access control, minimizing trust, and ensuring that all access requests are verified, making it an ideal choice for creating a secure environment.'
  },
    {
      questionText: 'Which of the following involves an attempt to take advantage of database misconfigurations?',
      answerOptions: [
        { answerText: 'Buffer overflow', isCorrect: false },
        { answerText: 'SQL injection', isCorrect: true },
        { answerText: 'VM escape', isCorrect: false },
        { answerText: 'Memory injection', isCorrect: false },
      ],
    explanation: 'My problem with this question is that it\'s not a misconfigured database that allows SQL injection, it\'s improperly sanitized user input fields in applications/web pages.'
  },
    {
      questionText: 'Which of the following is used to validate a certificate when it is presented to a user?',
      answerOptions: [
        { answerText: 'OCSP', isCorrect: true },
        { answerText: 'CSR', isCorrect: false },
        { answerText: 'CA', isCorrect: false },
        { answerText: 'CRC', isCorrect: false },
      ],
    explanation: 'CA issues and manages certificates. OSCP - Online Certificate Status Protocol, a protocol that checks a certificate for validity and if its been revoked (by the CA). The answer is OSCP. CA is like Congress, OSCP is like police. Congress records laws and writes them but don\'t actually enforce anything. Police enforce them'
  },
    {
      questionText: 'One of a company\'s vendors sent an analyst a security bulletin that recommends a BIOS update. Which of the following vulnerability types is being addressed by the patch?',
      answerOptions: [
        { answerText: 'Virtualization', isCorrect: false },
        { answerText: 'Firmware', isCorrect: true },
        { answerText: 'Application', isCorrect: false },
        { answerText: 'Operating system', isCorrect: false },
      ],
    explanation: 'Firmware is the correct answer because a BIOS update addresses vulnerabilities at the firmware level. The BIOS is an essential component of the system\'s firmware, and updates to it are intended to fix security vulnerabilities, improve compatibility, and enhance overall system stability.'
  },
    {
      questionText: 'Which of the following is used to quantitatively measure the criticality of a vulnerability?',
      answerOptions: [
        { answerText: 'CVE', isCorrect: false },
        { answerText: 'CVSS', isCorrect: true },
        { answerText: 'CIA', isCorrect: false },
        { answerText: 'CERT', isCorrect: false },
      ],
    explanation: 'Answer is B A - Common Vulnerabilities & Exposures is a dictionary of known threats. B - Common Vulnerability Scoring System quantifies how critical a vulnerability is. C - Confidentiality, Integrity & Availability is a security concept. D - Computer Emergency Response Team - the title speaks for itself!'
  },
    {
      questionText: 'Which of the following actions could a security engineer take to ensure workstations and servers are properly monitored for unauthorized changes and software?',
      answerOptions: [
        { answerText: 'Configure all systems to log scheduled tasks.', isCorrect: false },
        { answerText: 'Collect and monitor all traffic exiting the network.', isCorrect: false },
        { answerText: 'Block traffic based on known malicious signatures.', isCorrect: false },
        { answerText: 'Install endpoint management software on all systems', isCorrect: true },
      ],
    explanation: 'Install endpoint management software on all systems is the correct answer because it offers a comprehensive solution for monitoring and managing workstations and servers. Endpoint management software provides visibility into unauthorized changes, detects unapproved software installations, and enforces security policies, making it the most effective choice for ensuring system integrity and compliance.'
  },
    {
      questionText: 'An organization is leveraging a VPN between its headquarters and a branch location. Which of the following is the VPN protecting?',
      answerOptions: [
        { answerText: 'Data in use', isCorrect: false },
        { answerText: 'Data in transit', isCorrect: true },
        { answerText: 'Geographic restrictions', isCorrect: false },
        { answerText: 'Data sovereignty', isCorrect: false },
      ],
    explanation: 'Data in transit is the correct answer because a VPN is specifically designed to protect data as it moves between two locations. By encrypting the data and securing the communication path, the VPN ensures that information remains confidential and secure during transmission, making it the most relevant choice for this scenario.'
  },
    {
      questionText: 'After reviewing a vulnerability scanning report, a security analyst performs a test and confirms a vulnerability is a false positive. Which of the following would the security analyst conclude?',
      answerOptions: [
        { answerText: 'It is a false positive.', isCorrect: true },
        { answerText: 'A rescan is required.', isCorrect: false },
        { answerText: 'It is considered noise.', isCorrect: false },
        { answerText: 'Compensating controls exist.', isCorrect: false },
      ],
    explanation: 'False positive (A) would mean Telnet was incorrectly flagged as insecure—but Telnet is still a risk by default.\nCompensating controls (D) is correct because encryption helps mitigate the risk, but the risk still exists.'
  },
    {
      questionText: 'An organization disabled unneeded services and placed a firewall in front of a business-critical legacy system. Which of the following best describes the actions taken by the organization?',
      answerOptions: [
        { answerText: 'Exception', isCorrect: false },
        { answerText: 'Segmentation', isCorrect: false },
        { answerText: 'Risk transfer', isCorrect: false },
        { answerText: 'Compensating controls', isCorrect: true },
      ],
    explanation: 'The word "legacy" should inform that this action is compensating.'
  },
    {
      questionText: 'A security consultant needs secure, remote access to a client environment. Which of the following should the security consultant most likely use to gain access?',
      answerOptions: [
        { answerText: 'EAP', isCorrect: false },
        { answerText: 'DHCP', isCorrect: false },
        { answerText: 'IPSec', isCorrect: true },
        { answerText: 'NAT', isCorrect: false },
      ],
    explanation: 'IPSec is ideal for establishing a secure connection between a security consultant’s device and a client’s network, ensuring confidentiality, integrity, and authenticity of data transmitted over the connection.'
  },
    {
      questionText: 'Which of the following should a systems administrator use to ensure an easy deployment of resources within the cloud provider?',
      answerOptions: [
        { answerText: 'Software as a service', isCorrect: false },
        { answerText: 'Infrastructure as code', isCorrect: true },
        { answerText: 'Internet of Things', isCorrect: false },
        { answerText: 'Software-defined networking', isCorrect: false },
      ],
    explanation: 'Infrastructure as Code (IaC) is the correct answer because it provides the necessary tools and practices for automating and simplifying the deployment of infrastructure resources in a cloud environment. IaC enables efficient and repeatable resource provisioning, making it the most effective solution for the systems administrator\'s needs.'
  },
    {
      questionText: 'After a security awareness training session, a user called the IT help desk and reported a suspicious call. The suspicious caller stated that the Chief Financial Officer wanted credit card information in order to close an invoice. Which of the following topics did the user recognize from the training?',
      answerOptions: [
        { answerText: 'Insider threat', isCorrect: false },
        { answerText: 'Email phishing', isCorrect: false },
        { answerText: 'Social engineering', isCorrect: true },
        { answerText: 'Executive whaling', isCorrect: false },
      ],
    explanation: 'Executive whaling is when the CFO is one being targeted, therefore the answer is C'
  },
    {
      questionText: 'A security administrator is deploying a DLP solution to prevent the exfiltration of sensitive customer data. Which of the following should the administrator do first?',
      answerOptions: [
        { answerText: 'Block access to cloud storage websites.', isCorrect: false },
        { answerText: 'Create a rule to block outgoing email attachments.', isCorrect: false },
        { answerText: 'Apply classifications to the data.', isCorrect: true },
        { answerText: 'Remove all user permissions from shares on the file server.', isCorrect: false },
      ],
    explanation: 'Apply classifications to the data is the correct first step because it establishes a foundational understanding of what data is sensitive and needs protection. By classifying the data, the security administrator can ensure that subsequent DLP policies are effectively tailored to prevent the exfiltration of sensitive customer data, while minimizing unnecessary restrictions on non-sensitive data.'
  },
    {
      questionText: 'An administrator assists the legal and compliance team with ensuring information about customer transactions is archived for the proper time period. Which of the following data policies is the administrator carrying out?',
      answerOptions: [
        { answerText: 'Compromise', isCorrect: false },
        { answerText: 'Retention', isCorrect: true },
        { answerText: 'Analysis', isCorrect: false },
        { answerText: 'Transfer', isCorrect: false },
        { answerText: 'Inventory', isCorrect: false },
      ],
    explanation: 'The administrator is tasked with ensuring that transaction data is archived for the appropriate duration. This task involves adhering to retention schedules that dictate how long such data must be kept to meet compliance obligations. Retention policies are critical for legal and compliance teams, as they help avoid legal issues related to data disposal and ensure that records are available for audits, investigations, or regulatory reviews.'
  },
    {
      questionText: 'A company is working with a vendor to perform a penetration test. Which of the following includes an estimate about the number of hours required to complete the engagement?',
      answerOptions: [
        { answerText: 'SOW', isCorrect: true },
        { answerText: 'BPA', isCorrect: false },
        { answerText: 'SLA', isCorrect: false },
        { answerText: 'NDA', isCorrect: false },
      ],
    explanation: 'SOW: statement of work BPA: business partnership agreement SLA: service level agreement NDA: no disclosure agreement'
  },
    {
      questionText: 'A Chief Information Security Officer (CISO) wants to explicitly raise awareness about the increase of ransomware-as-a-service in a report to the management team. Which of the following best describes the threat actor in the CISO’s report?',
      answerOptions: [
        { answerText: 'Insider threat', isCorrect: false },
        { answerText: 'Hacktivist', isCorrect: false },
        { answerText: 'Nation-state', isCorrect: false },
        { answerText: 'Organized crime', isCorrect: true },
      ],
    explanation: 'Ransomware is blackmailing for monetary gain which is a CRIME. It also does not fit the criteria for any other threat actor listed.'
  },
    {
      questionText: 'Which of the following practices would be best to prevent an insider from introducing malicious code into a company\'s development process?',
      answerOptions: [
        { answerText: 'Code scanning for vulnerabilities', isCorrect: false },
        { answerText: 'Open-source component usage', isCorrect: false },
        { answerText: 'Quality assurance testing', isCorrect: false },
        { answerText: 'Peer review and approval', isCorrect: true },
      ],
    explanation: 'The key word here is prevent. Peer reviews help catch malicious code before it is integrated into the production environment by having multiple sets of eyes on the changes, reducing the chance of any one developer slipping harmful code through the process.'
  },
    {
      questionText: 'Which of the following can best protect against an employee inadvertently installing malware on a company system?',
      answerOptions: [
        { answerText: 'Host-based firewall', isCorrect: false },
        { answerText: 'System isolation', isCorrect: false },
        { answerText: 'Least privilege', isCorrect: false },
        { answerText: 'Application allow list', isCorrect: true },
      ],
    explanation: 'By using an application allow list, employees cannot inadvertently install or run unauthorized software, including malware, because only approved applications are permitted to execute. This approach minimizes the risk of malware introduction through accidental downloads or installations.'
  },
    {
      questionText: 'A company is adding a clause to its AUP that states employees are not allowed to modify the operating system on mobile devices. Which of the following vulnerabilities is the organization addressing?',
      answerOptions: [
        { answerText: 'Cross-site scripting', isCorrect: false },
        { answerText: 'Buffer overflow', isCorrect: false },
        { answerText: 'Jailbreaking', isCorrect: true },
        { answerText: 'Side loading', isCorrect: false },
      ],
    explanation: 'My first thought was: D - because jailbreaking only relates to iOS and rooting is Android. They didn\'t specify a device. However... The question relates to modifying the OS, not installing unofficial apps. So, although no OS is specified, answer C does seem most logical. It pays to take a little more time to dissect the wording of the question as much as possible.'
  },
    {
      questionText: 'Which of the following would be the best ways to ensure only authorized personnel can access a secure facility? (Choose two.)',
      answerOptions: [
        { answerText: 'Fencing', isCorrect: false },
        { answerText: 'Video surveillance', isCorrect: false },
        { answerText: 'Badge access', isCorrect: true },
        { answerText: 'Access control vestibule', isCorrect: true },
        { answerText: 'Sign-in sheet', isCorrect: false },
        { answerText: 'Sensor', isCorrect: false },
      ],
    explanation: '• C. Badge access • D. Access control vestibule'
  },
    {
      questionText: 'An organization would like to store customer data on a separate part of the network that is not accessible to users on the main corporate network. Which of the following should the administrator use to accomplish this goal?',
      answerOptions: [
        { answerText: 'Segmentation', isCorrect: true },
        { answerText: 'Isolation', isCorrect: false },
        { answerText: 'Patching', isCorrect: false },
        { answerText: 'Encryption', isCorrect: false },
      ],
    explanation: 'Mentions the org wants to store it on the network just separate from the main network, which is segmentation.'
  },
    {
      questionText: 'Which of the following is the most common data loss path for an air-gapped network?',
      answerOptions: [
        { answerText: 'Bastion host', isCorrect: false },
        { answerText: 'Unsecured Bluetooth', isCorrect: false },
        { answerText: 'Unpatched OS', isCorrect: false },
        { answerText: 'Removable devices', isCorrect: true },
      ],
    explanation: 'In an air-gapped network, which is physically isolated from other networks, the most common data loss path would typically be through removable devices (option D). These can include USB drives, external hard drives, or other storage devices that could be introduced into the network, intentionally or unintentionally, by users or external entities. This is because such devices can bypass the physical isolation of the air gap and introduce potential security vulnerabilities.'
  },
    {
      questionText: 'Malware spread across a company\'s network after an employee visited a compromised industry blog. Which of the following best describes this type of attack?',
      answerOptions: [
        { answerText: 'Impersonation', isCorrect: false },
        { answerText: 'Disinformation', isCorrect: false },
        { answerText: 'Watering-hole', isCorrect: true },
        { answerText: 'Smishing', isCorrect: false },
      ],
    explanation: 'Watering-hole is the correct answer because it describes the method used by the attacker to compromise a legitimate website frequented by the target group (in this case, the industry blog) and spread malware to visitors. This strategic targeting and delivery mechanism is characteristic of a watering-hole attack.'
  },
    {
      questionText: 'An organization is struggling with scaling issues on its VPN concentrator and internet circuit due to remote work. The organization is looking for a software solution that will allow it to reduce traffic on the VPN and internet circuit, while still providing encrypted tunnel access to the data center and monitoring of remote employee internet traffic. Which of the following will help achieve these objectives?',
      answerOptions: [
        { answerText: 'Deploying a SASE solution to remote employees', isCorrect: true },
        { answerText: 'Building a load-balanced VPN solution with redundant internet', isCorrect: false },
        { answerText: 'Purchasing a low-cost SD-WAN solution for VPN traffic', isCorrect: false },
        { answerText: 'Using a cloud provider to create additional VPN concentrators', isCorrect: false },
      ],
    explanation: 'Answer is A......SASE (Secure Access Service Edge) is a comprehensive networking and security approach that combines wide-area networking (WAN) capabilities with security features. It provides secure access to applications and data, including encrypted tunnel access to the data center, while also offering monitoring capabilities for remote employee internet traffic. By implementing a SASE solution, the organization can reduce traffic on the VPN and internet circuit by routing traffic intelligently through the cloud, closer to the users. This approach helps optimize performance and security, addressing the scaling issues effectively.'
  },
    {
      questionText: 'Which of the following is the best reason to complete an audit in a banking environment?',
      answerOptions: [
        { answerText: 'Regulatory requirement', isCorrect: true },
        { answerText: 'Organizational change', isCorrect: false },
        { answerText: 'Self-assessment requirement', isCorrect: false },
        { answerText: 'Service-level requirement', isCorrect: false },
      ],
    explanation: 'Financial services are heavily regulated.'
  },
    {
      questionText: 'Which of the following security concepts is the best reason for permissions on a human resources fileshare to follow the principle of least privilege?',
      answerOptions: [
        { answerText: 'Integrity', isCorrect: false },
        { answerText: 'Availability', isCorrect: false },
        { answerText: 'Confidentiality', isCorrect: true },
        { answerText: 'Non-repudiation', isCorrect: false },
      ],
    explanation: 'Human resources (HR) data typically includes sensitive information such as employee records, personal data, salaries, and other confidential details. Implementing the principle of least privilege ensures that only authorized HR personnel have access to this sensitive information, maintaining its confidentiality. Access Control: By granting access only to those who require it to perform their job functions, the organization minimizes the risk of unauthorized access, data breaches, and information leaks. The primary goal of applying least privilege to HR files is to protect sensitive data from unauthorized access, aligning directly with the confidentiality aspect of information security.'
  },
    {
      questionText: 'Which of the following are cases in which an engineer should recommend the decommissioning of a network device? (Choose two.)',
      answerOptions: [
        { answerText: 'The device has been moved from a production environment to a test environment.', isCorrect: false },
        { answerText: 'The device is configured to use cleartext passwords.', isCorrect: false },
        { answerText: 'The device is moved to an isolated segment on the enterprise network.', isCorrect: false },
        { answerText: 'The device is moved to a different location in the enterprise.', isCorrect: false },
        { answerText: 'The device\'s encryption level cannot meet organizational standards.', isCorrect: true },
        { answerText: 'The device is unable to receive authorized updates.', isCorrect: true },
      ],
    explanation: 'E. The device\'s encryption level cannot meet organizational standards. F. The device is unable to receive authorized updates. These two cases justify decommissioning a network device: - Encryption Level: If a device\'s encryption level cannot meet the organization\'s standards, it poses a significant security risk and should be decommissioned. - Authorized Updates: If a device is unable to receive authorized updates, it becomes vulnerable to known exploits and cannot be maintained securely, thus it should also be decommissioned. Therefore, the correct answers are: E. The device\'s encryption level cannot meet organizational standards. F. The device is unable to receive authorized updates.'
  },
    {
      questionText: 'A company is required to perform a risk assessment on an annual basis. Which of the following types of risk assessments does this requirement describe?',
      answerOptions: [
        { answerText: 'Continuous', isCorrect: false },
        { answerText: 'Ad hoc', isCorrect: false },
        { answerText: 'Recurring', isCorrect: true },
        { answerText: 'One time', isCorrect: false },
      ],
    explanation: 'Continous: Its not because that would mean running software continously to evaluate risks Ad hoc: its not because that one is as the name implies decided to be done on the spur of the moment (or as a reaction) Reccuring: yes because its something pre planned which reoccurs One time: Per year means every year, not just one time'
  },
    {
      questionText: 'After a recent ransomware attack on a company\'s system, an administrator reviewed the log files. Which of the following control types did the administrator use?',
      answerOptions: [
        { answerText: 'Compensating', isCorrect: false },
        { answerText: 'Detective', isCorrect: true },
        { answerText: 'Preventive', isCorrect: false },
        { answerText: 'Corrective', isCorrect: false },
      ],
    explanation: 'The administrator used detective controls by reviewing the log files after the ransomware attack. Detective controls are designed to detect and identify potential security incidents or policy violations that may have occurred within an organization\'s systems or network. In this case, the log files were analyzed to identify signs of the ransomware attack and understand how the incident occurred.'
  },
    {
      questionText: 'Which of the following exercises should an organization use to improve its incident response process?',
      answerOptions: [
        { answerText: 'Tabletop', isCorrect: true },
        { answerText: 'Replication', isCorrect: false },
        { answerText: 'Failover', isCorrect: false },
        { answerText: 'Recovery', isCorrect: false },
      ],
    explanation: 'Tabletop is the correct answer because tabletop exercises are specifically designed to evaluate and improve incident response processes by allowing teams to simulate responses to hypothetical incidents. This exercise provides valuable insights into the effectiveness of the current response plan and identifies areas for improvement, enhancing the organization\'s overall incident response capabilities.'
  },
    {
      questionText: 'Which of the following best ensures minimal downtime and data loss for organizations with critical computing equipment located in earthquake-prone areas?',
      answerOptions: [
        { answerText: 'Generators and UPS', isCorrect: false },
        { answerText: 'Off-site replication', isCorrect: true },
        { answerText: 'Redundant cold sites', isCorrect: false },
        { answerText: 'High availability networking', isCorrect: false },
      ],
    explanation: 'B. Off-site replication While all options are important for disaster recovery, off-site replication is the most effective way to ensure minimal downtime and data loss in the event of an earthquake. By replicating critical data to a remote location, organizations can quickly restore operations in the event of a disaster.'
  },
    {
      questionText: 'A newly identified network access vulnerability has been found in the OS of legacy IoT devices. Which of the following would best mitigate this vulnerability quickly?',
      answerOptions: [
        { answerText: 'Insurance', isCorrect: false },
        { answerText: 'Patching', isCorrect: false },
        { answerText: 'Segmentation', isCorrect: true },
        { answerText: 'Replacement', isCorrect: false },
      ],
    explanation: 'I\'ve not heard of patching legacy devices... Professor Messer would be disappointed.'
  },
    {
      questionText: 'After an audit, an administrator discovers all users have access to confidential data on a file server. Which of the following should the administrator use to restrict access to the data quickly?',
      answerOptions: [
        { answerText: 'Group Policy', isCorrect: false },
        { answerText: 'Content filtering', isCorrect: false },
        { answerText: 'Data loss prevention', isCorrect: false },
        { answerText: 'Access control lists', isCorrect: true },
      ],
    explanation: 'Access control lists (ACLs) should be used to restrict access to the data quickly. ACLs allow the administrator to specify which users or groups have permission to access certain files or directories on the file server, providing a straightforward and immediate way to enforce access controls and protect confidential data.'
  },
    {
      questionText: 'A client demands at least 99.99% uptime from a service provider\'s hosted security services. Which of the following documents includes the information the service provider should return to the client?',
      answerOptions: [
        { answerText: 'MOA', isCorrect: false },
        { answerText: 'SOW', isCorrect: false },
        { answerText: 'MOU', isCorrect: false },
        { answerText: 'SLA', isCorrect: true },
      ],
    explanation: 'In this scenario, the client demands 99.99% uptime for hosted security services. The SLA is the appropriate document to specify this uptime requirement and any associated metrics.\n\nMOA - memorandum of Agreement\nMOU - Memorandum of Understanding\nSOW - Statement / Scope of WorkSLA - Service Level Agreement'
  },
    {
      questionText: 'A company is discarding a classified storage array and hires an outside vendor to complete the disposal. Which of the following should the company request from the vendor?',
      answerOptions: [
        { answerText: 'Certification', isCorrect: true },
        { answerText: 'Inventory list', isCorrect: false },
        { answerText: 'Classification', isCorrect: false },
        { answerText: 'Proof of ownership', isCorrect: false },
      ],
    explanation: 'Third-party certificate of destruction, proof it was actually disposed'
  },
    {
      questionText: 'A company is planning a disaster recovery site and needs to ensure that a single natural disaster would not result in the complete loss of regulated backup data. Which of the following should the company consider?',
      answerOptions: [
        { answerText: 'Geographic dispersion', isCorrect: true },
        { answerText: 'Platform diversity', isCorrect: false },
        { answerText: 'Hot site', isCorrect: false },
        { answerText: 'Load balancing', isCorrect: false },
      ],
    explanation: 'Answer: A Geographic dispersion is the practice of having backup data stored in different locations that are far enough apart to minimize the risk of a single natural disaster affecting both sites. This ensures that the company can recover its regulated data in case of a disaster at the primary site. Platform diversity, hot site, and load balancing are not directly related to the protection of backup data from natural disasters.Reference:CompTIA Security+ Study Guide: Exam SY0-701, 9th Edition, page 449;Disaster Recovery Planning: Geographic Diversity'
  },
    {
      questionText: 'A security analyst locates a potentially malicious video file on a server and needs to identify both the creation date and the file\'s creator. Which of the following actions would most likely give the security analyst the information required?',
      answerOptions: [
        { answerText: 'Obtain the file\'s SHA-256 hash.', isCorrect: false },
        { answerText: 'Use hexdump on the file\'s contents.', isCorrect: false },
        { answerText: 'Check endpoint logs.', isCorrect: false },
        { answerText: 'Query the file\'s metadata.', isCorrect: true },
      ],
    explanation: 'Red = offensive\n Blue = defensive\n Yellow = builders\n Purple = mix of offensive and defensive. Also the color you get when you mix red and blue'
  },
    {
      questionText: 'Which of the following teams combines both offensive and defensive testing techniques to protect an organization\'s critical systems?',
      answerOptions: [
        { answerText: 'Red', isCorrect: false },
        { answerText: 'Blue', isCorrect: false },
        { answerText: 'Purple', isCorrect: true },
        { answerText: 'Yellow', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'A small business uses kiosks on the sales floor to display product information for customers. A security team discovers the kiosks use end-of-life operating systems. Which of the following is the security team most likely to document as a security implication of the current architecture?',
      answerOptions: [
        { answerText: 'Patch availability', isCorrect: true },
        { answerText: 'Product software compatibility', isCorrect: false },
        { answerText: 'Ease of recovery', isCorrect: false },
        { answerText: 'Cost of replacement', isCorrect: false },
      ],
    explanation: 'The most likely security implication that the security team would document is patch availability. End-of-life operating systems no longer receive security updates or patches from the vendor, which leaves them vulnerable to newly discovered exploits and vulnerabilities. This lack of ongoing support means that any security flaws found in the operating systems will not be addressed, increasing the risk of compromise.'
  },
    {
      questionText: 'Which of the following would help ensure a security analyst is able to accurately measure the overall risk to an organization when a new vulnerability is disclosed?',
      answerOptions: [
        { answerText: 'A full inventory of all hardware and software', isCorrect: true },
        { answerText: 'Documentation of system classifications', isCorrect: false },
        { answerText: 'A list of system owners and their departments', isCorrect: false },
        { answerText: 'Third-party risk assessment documentation', isCorrect: false },
      ],
    explanation: 'Conducting inventory is part of risk management, so knowing what is in your environment will be very helpful to track and patch'
  },
    {
      questionText: 'Which of the following best practices gives administrators a set period to perform changes to an operational system to ensure availability and minimize business impacts?',
      answerOptions: [
        { answerText: 'Impact analysis', isCorrect: false },
        { answerText: 'Scheduled downtime', isCorrect: true },
        { answerText: 'Backout plan', isCorrect: false },
        { answerText: 'Change management boards', isCorrect: false },
      ],
    explanation: 'Set time aside for IT to make changes, like a maintenance window, typically not during peak hours'
  },
    {
      questionText: 'A company must ensure sensitive data at rest is rendered unreadable. Which of the following will the company most likely use?',
      answerOptions: [
        { answerText: 'Hashing', isCorrect: false },
        { answerText: 'Tokenization', isCorrect: false },
        { answerText: 'Encryption', isCorrect: true },
        { answerText: 'Segmentation', isCorrect: false },
      ],
    explanation: 'To ensure sensitive data at rest is rendered unreadable, the company will most likely use encryption. Encryption transforms the data into an unreadable format using an algorithm and a key, and only authorized parties with the correct decryption key can convert it back to its original readable form. This is the most effective way to protect data at rest from unauthorized access.'
  },
    {
      questionText: 'A legacy device is being decommissioned and is no longer receiving updates or patches. Which of the following describes this scenario?',
      answerOptions: [
        { answerText: 'End of business', isCorrect: false },
        { answerText: 'End of testing', isCorrect: false },
        { answerText: 'End of support', isCorrect: true },
        { answerText: 'End of life', isCorrect: false },
      ],
    explanation: '• D. End of life'
  },
    {
      questionText: 'A bank insists all of its vendors must prevent data loss on stolen laptops. Which of the following strategies is the bank requiring?',
      answerOptions: [
        { answerText: 'Encryption at rest', isCorrect: true },
        { answerText: 'Masking', isCorrect: false },
        { answerText: 'Data classification', isCorrect: false },
        { answerText: 'Permission restrictions', isCorrect: false },
      ],
    explanation: 'When a laptop is stolen, encryption at rest ensures that the data remains secure and inaccessible to the thief, as they would need the decryption key to access the files. Data Protection: Encryption at rest provides a robust layer of security for sensitive data, making it a common requirement for organizations handling confidential information. The primary concern with stolen laptops is unauthorized access to the data stored on them. Encryption at rest is the most effective way to prevent data loss in this scenario, as it keeps the data secure even if the device falls into the wrong hands.'
  },
    {
      questionText: 'A company\'s end users are reporting that they are unable to reach external websites. After reviewing the performance data for the DNS severs, the analyst discovers that the CPU, disk, and memory usage are minimal, but the network interface is flooded with inbound traffic. Network logs show only a small number of DNS queries sent to this server. Which of the following best describes what the security analyst is seeing?',
      answerOptions: [
        { answerText: 'Concurrent session usage', isCorrect: false },
        { answerText: 'Secure DNS cryptographic downgrade', isCorrect: false },
        { answerText: 'On-path resource consumption', isCorrect: false },
        { answerText: 'Reflected denial of service', isCorrect: true },
      ],
    explanation: ''
  },
    {
      questionText: 'A systems administrator wants to prevent users from being able to access data based on their responsibilities. The administrator also wants to apply the required access structure via a simplified format. Which of the following should the administrator apply to the site recovery resource group?',
      answerOptions: [
        { answerText: 'RBAC', isCorrect: true },
        { answerText: 'ACL', isCorrect: false },
        { answerText: 'SAML', isCorrect: false },
        { answerText: 'GPO', isCorrect: false },
      ],
    explanation: 'Role-based access control (RBAC) restricts users to only access data based on their job responsibilities.'
  },  
     {
      questionText: "During the onboarding process, an employee needs to create a password for an intranet account. The password must include ten characters, numbers, and letters, and two special characters. Once the password is created, the company will grant the employee access to other company-owned websites based on the intranet profile. Which of the following access management concepts is the company most likely using to safeguard intranet accounts and grant access to multiple sites based on a user's intranet account? (Choose two.)",
      answerOptions: [
        { answerText: 'Federation', isCorrect: true },
        { answerText: 'Identity proofing', isCorrect: false },
        { answerText: 'Password complexity', isCorrect: true },
        { answerText: 'Default password changes', isCorrect: false },
        { answerText: 'Password manager', isCorrect: false },
        { answerText: 'Open authentication', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'Which of the following describes a security alerting and monitoring tool that collects system, application, and network logs from multiple sources in a centralized system?',
      answerOptions: [
        { answerText: 'SIEM', isCorrect: true },
        { answerText: 'DLP', isCorrect: false },
        { answerText: 'IDS', isCorrect: false },
        { answerText: 'SNMP', isCorrect: false },
      ],
    explanation: 'SIEM is the correct answer because SIEM systems are specifically designed to collect, centralize, and analyze logs from multiple sources, providing security alerting and monitoring capabilities essential for detecting and responding to potential threats.'
  },
    {
      questionText: "A network manager wants to protect the company's VPN by implementing multifactor authentication that uses:Something you know -Something you have -Something you are -Which of the following would accomplish the manager's goal?",
      answerOptions: [
        { answerText: 'Domain name, PKI, GeoIP lookup', isCorrect: false },
        { answerText: 'VPN IP address, company ID, facial structure', isCorrect: false },
        { answerText: 'Password, authentication token, thumbprint', isCorrect: true },
        { answerText: 'Company URL, TLS certificate, home address', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'Which of the following would be the best way to handle a critical business application that is running on a legacy server?',
      answerOptions: [
        { answerText: 'Segmentation', isCorrect: true },
        { answerText: 'Isolation', isCorrect: false },
        { answerText: 'Hardening', isCorrect: false },
        { answerText: 'Decommissioning', isCorrect: false },
      ],
    explanation: 'A. Segmentation Segmentation is the best approach to handle a critical business application running on a legacy server. By segmenting the legacy server from the rest of the network, you can limit the potential impact of any vulnerabilities associated with the legacy system. This approach allows the critical application to continue running while minimizing the risk to the rest of the network. Therefore, the correct answer is: A. Segmentation'
  },
    {
      questionText: 'Which of the following vulnerabilities is exploited when an attacker overwrites a register with a malicious address?',
      answerOptions: [
        { answerText: 'VM escape', isCorrect: false },
        { answerText: 'SQL injection', isCorrect: false },
        { answerText: 'Buffer overflow', isCorrect: true },
        { answerText: 'Race condition', isCorrect: false },
      ],
    explanation: 'The scenario specifically mentions overwriting a register with a malicious address, which is a hallmark of a buffer overflow attack. This technique is commonly used to redirect the program to execute malicious instructions, making buffer overflow the most relevant vulnerability here. In a buffer overflow attack, the attacker might overwrite a register or a return address on the stack with a malicious address, redirecting the program\'s control flow to execute arbitrary code.'
  },
    {
      questionText: "After a company was compromised, customers initiated a lawsuit. The company's attorneys have requested that the security team initiate a legal hold in response to the lawsuit. Which of the following describes the action the security team will most likely be required to take?",
      answerOptions: [
        { answerText: 'Retain the emails between the security team and affected customers for 30 days.', isCorrect: false },
        { answerText: 'Retain any communications related to the security breach until further notice.', isCorrect: true },
        { answerText: 'Retain any communications between security members during the breach response.', isCorrect: false },
        { answerText: 'Retain all emails from the company to affected customers for an indefinite period of time.', isCorrect: false },
      ],
    explanation: 'Retain any communications related to the security breach until further notice is the correct answer. This approach ensures that all relevant evidence is preserved in compliance with the legal hold, covering the full scope of communications and documents needed for the lawsuit. It aligns with the purpose of a legal hold, which is to safeguard all potential evidence until the legal proceedings are complete.'
  },
    {
      questionText: 'Which of the following describes the process of concealing code or text inside a graphical image?',
      answerOptions: [
        { answerText: 'Symmetric encryption', isCorrect: false },
        { answerText: 'Hashing', isCorrect: false },
        { answerText: 'Data masking', isCorrect: false },
        { answerText: 'Steganography', isCorrect: true },
      ],
    explanation: 'Steganography is the correct answer because it specifically involves the process of concealing code or text inside a graphical image, allowing information to be hidden in plain sight. This technique is unique in its ability to embed data within another medium, making it distinct from other security and privacy techniques like encryption, hashing, or data masking.'
  },
    {
      questionText: 'An employee receives a text message from an unknown number claiming to be the company’s Chief Executive Officer and asking the employee to purchase several gift cards. Which of the following types of attacks does this describe?',
      answerOptions: [
        { answerText: 'Vishing', isCorrect: false },
        { answerText: 'Smishing', isCorrect: true },
        { answerText: 'Pretexting', isCorrect: false },
        { answerText: 'Phishing', isCorrect: false },
      ],
    explanation: 'Smishing is the correct answer because the attack is conducted via SMS text messages, and the goal is to manipulate the employee into taking action (purchasing gift cards) based on fraudulent communication. Smishing precisely captures the medium and technique used in this type of social engineering attack.'
  },
    {
      questionText: 'Which of the following risk management strategies should an enterprise adopt first if a legacy application is critical to business operations and there are preventative controls that are not yet implemented?',
      answerOptions: [
        { answerText: 'Mitigate', isCorrect: true },
        { answerText: 'Accept', isCorrect: false },
        { answerText: 'Transfer', isCorrect: false },
        { answerText: 'Avoid', isCorrect: false },
      ],
    explanation: 'A. Mitigate When a legacy application is critical to business operations and there are preventative controls that are not yet implemented, the first risk management strategy an enterprise should adopt is to mitigate the risks. This involves implementing measures to reduce the risk to an acceptable level. Mitigation can include steps such as patching vulnerabilities, applying compensating controls, segmenting the network, and hardening the application and its environment. Therefore, the correct answer is: A. Mitigate'
  },
    {
      questionText: 'Visitors to a secured facility are required to check in with a photo ID and enter the facility through an access control vestibule. Which of the following best describes this form of security control?',
      answerOptions: [
        { answerText: 'Physical', isCorrect: true },
        { answerText: 'Managerial', isCorrect: false },
        { answerText: 'Technical', isCorrect: false },
        { answerText: 'Operational', isCorrect: false },
      ],
    explanation: 'A) Physical: This is a physical security control because it involves physical barriers and measures to control access to the facility, such as checking photo IDs and using an access control vestibule. B) Managerial: Managerial controls are policies, procedures, and guidelines established by an organization to ensure security compliance and oversight. This scenario is more focused on physical actions than managerial oversight. C) Technical: Technical controls involve systems and software (e.g., firewalls, encryption) that secure data and systems electronically. The scenario here involves people and physical infrastructure, not technology. D) Operational: Operational controls are implemented by people in their day-to-day activities, such as security training or incident response. While the scenario involves operational tasks, the primary focus is on physical security measures. In summary, physical controls like ID checks and vestibules are examples of barriers to control access to secure areas, making A) Physical the best choice.'
  },
    {
      questionText: "The local administrator account for a company's VPN appliance was unexpectedly used to log in to the remote management interface. Which of the following would have most likely prevented this from happening?",
      answerOptions: [
        { answerText: 'Using least privilege', isCorrect: false },
        { answerText: 'Changing the default password', isCorrect: true },
        { answerText: 'Assigning individual user IDs', isCorrect: false },
        { answerText: 'Reviewing logs more frequently', isCorrect: false },
      ],
    explanation: 'Keyword "unexpectedly" and "logged in". if expected it would be with privilege. But not known Somebody could have cracked an easy password.'
  },
    {
      questionText: 'Which of the following is the best way to secure an on-site data center against intrusion from an insider?',
      answerOptions: [
        { answerText: 'Bollards', isCorrect: false },
        { answerText: 'Access badge', isCorrect: true },
        { answerText: 'Motion sensor', isCorrect: false },
        { answerText: 'Video surveillance', isCorrect: false },
      ],
    explanation: 'Wouldn\'t an insider have a badge?'
  },
    {
      questionText: "An engineer moved to another team and is unable to access the new team's shared folders while still being able to access the shared folders from the former team. After opening a ticket, the engineer discovers that the account was never moved to the new group. Which of the following access controls is most likely causing the lack of access?",
      answerOptions: [
        { answerText: 'Role-based', isCorrect: true },
        { answerText: 'Discretionary', isCorrect: false },
        { answerText: 'Time of day', isCorrect: false },
        { answerText: 'Least privilege', isCorrect: false },
      ],
    explanation: 'Role-based is the correct answer because the issue arises from the engineer\'s account not being updated to include the new role associated with the new team\'s shared folders. Role-Based Access Control is the framework in place that determines access based on roles assigned to users, making it the most relevant explanation for the engineer\'s access issue.'
  },
    {
      questionText: 'Which of the following factors are the most important to address when formulating a training curriculum plan for a security awareness program? (Choose two.)',
      answerOptions: [
        { answerText: 'Channels by which the organization communicates with customers', isCorrect: false },
        { answerText: 'The reporting mechanisms for ethics violations', isCorrect: false },
        { answerText: 'Threat vectors based on the industry in which the organization operates', isCorrect: true },
        { answerText: 'Secure software development training for all personnel', isCorrect: false },
        { answerText: 'Cadence and duration of training events', isCorrect: true },
        { answerText: 'Retraining requirements for individuals who fail phishing simulations', isCorrect: false },
      ],
    explanation: 'C. Threat vectors based on the industry in which the organization operates E. Cadence and duration of training events When formulating a training curriculum plan for a security awareness program, it is crucial to focus on: - Threat vectors based on the industry in which the organization operates (C): Understanding the specific threats that are most relevant to the industry helps tailor the training content to address the most pressing risks and vulnerabilities that employees might face. - Cadence and duration of training events (E): Establishing an appropriate schedule and duration for training ensures that employees receive regular, ongoing education to keep security top-of-mind and adapt to evolving threats. Therefore, the correct answers are: C. Threat vectors based on the industry in which the organization operates E. Cadence and duration of training events'
  },
    {
      questionText: "A network administrator is working on a project to deploy a load balancer in the company's cloud environment. Which of the following fundamental security requirements does this project fulfil?",
      answerOptions: [
        { answerText: 'Privacy', isCorrect: false },
        { answerText: 'Integrity', isCorrect: false },
        { answerText: 'Confidentiality', isCorrect: false },
        { answerText: 'Availability', isCorrect: true },
      ],
    explanation: ''
  },
    {
      questionText: 'A systems administrator is changing the password policy within an enterprise environment and wants this update implemented on all systems as quickly as possible. Which of the following operating system security measures will the administrator most likely use?',
      answerOptions: [
        { answerText: 'Deploying PowerShell scripts', isCorrect: false },
        { answerText: 'Pushing GPO update', isCorrect: true },
        { answerText: 'Enabling PAP', isCorrect: false },
        { answerText: 'Updating EDR profiles', isCorrect: false },
      ],
    explanation: '​Group Policy Objects (GPOs) provides an infrastructure for centralized configuration management of the Windows operating system and applications that run on the operating system. GPOs are a collection of settings that define what a system will look like and how it will behave for a defined group of computers or users.'
  },
    {
      questionText: 'Which of the following would be most useful in determining whether the long-term cost to transfer a risk is less than the impact of the risk?',
      answerOptions: [
        { answerText: 'ARO', isCorrect: false },
        { answerText: 'RTO', isCorrect: false },
        { answerText: 'RPO', isCorrect: false },
        { answerText: 'ALE', isCorrect: true },
        { answerText: 'SLE', isCorrect: false },
      ],
    explanation: 'ALE (Annual Loss Expectancy) represents the expected monetary loss for an asset due to a risk over a year. It is calculated by multiplying the Annual Rate of Occurrence (ARO) by the Single Loss Expectancy (SLE). This provides a clear picture of the financial impact of a risk over time.'
  },
    {
      questionText: 'In order to strengthen a password and prevent a hacker from cracking it, a random string of 36 characters was added to the password. Which of the following best describes this technique?',
      answerOptions: [
        { answerText: 'Key stretching', isCorrect: false },
        { answerText: 'Tokenization', isCorrect: false },
        { answerText: 'Data masking', isCorrect: false },
        { answerText: 'Salting', isCorrect: true },
      ],
    explanation: 'Salting is the correct answer because it involves adding a random string to a password before hashing to strengthen security. This technique effectively prevents precomputed hash attacks, making it a critical component of modern password protection strategies.'
  },
    {
      questionText: 'A technician is deploying a new security camera. Which of the following should the technician do?',
      answerOptions: [
        { answerText: 'Configure the correct VLAN.', isCorrect: false },
        { answerText: 'Perform a vulnerability scan.', isCorrect: false },
        { answerText: 'Disable unnecessary ports.', isCorrect: false },
        { answerText: 'Conduct a site survey.', isCorrect: true },
      ],
    explanation: 'D. Conduct a site survey. Before deploying a new security camera, conducting a site survey is crucial. A site survey helps determine the optimal placement of the camera, assesses environmental factors, ensures there are no blind spots, and verifies that the camera will effectively cover the desired area. It also helps in planning for network connectivity, power supply, and other logistical considerations. Therefore, the correct answer is: D. Conduct a site survey.'
  },
    {
      questionText: "A company is experiencing a web services outage on the public network. The services are up and available but inaccessible. The network logs show a sudden increase in network traffic that is causing the outage. Which of the following attacks is the organization experiencing?",
      answerOptions: [
        { answerText: 'ARP poisoning', isCorrect: false },
        { answerText: 'Brute force', isCorrect: false },
        { answerText: 'Buffer overflow', isCorrect: false },
        { answerText: 'DDoS', isCorrect: true },
      ],
    explanation: ''
  },
    {
      questionText: 'Which of the following threat actors is the most likely to be motivated by profit?',
      answerOptions: [
        { answerText: 'Hacktivist', isCorrect: false },
        { answerText: 'Insider threat', isCorrect: false },
        { answerText: 'Organized crime', isCorrect: true },
        { answerText: 'Shadow IT', isCorrect: false },
      ],
    explanation: 'Profit is the main driver for organized crime, making them the most likely threat actor motivated by financial incentives. They are structured to exploit opportunities that result in monetary rewards. Therefore, Organized crime is the correct answer because organized crime groups are primarily driven by the pursuit of financial gain. They engage in cyber activities designed to steal, extort, or otherwise generate profit, making them the most profit-motivated threat actor in this context.'
  },
    {
      questionText: 'An organization experiences a cybersecurity incident involving a command-and-control server. Which of the following logs should be analyzed to identify the impacted host? (Choose two.)',
      answerOptions: [
        { answerText: 'Application', isCorrect: false },
        { answerText: 'Authentication', isCorrect: false },
        { answerText: 'DHCP', isCorrect: false },
        { answerText: 'Network', isCorrect: true },
        { answerText: 'Firewall', isCorrect: true },
        { answerText: 'Database', isCorrect: false },
      ],
    explanation: 'D. Network E. Firewall'
  },
    {
      questionText: 'During a penetration test, a vendor attempts to enter an unauthorized area using an access badge. Which of the following types of tests does this represent?',
      answerOptions: [
        { answerText: 'Defensive', isCorrect: false },
        { answerText: 'Passive', isCorrect: false },
        { answerText: 'Offensive', isCorrect: false },
        { answerText: 'Physical', isCorrect: true },
      ],
    explanation: 'Isn\'t this both physical and offensive?'
  },
    {
      questionText: 'A systems administrator uses a key to encrypt a message being sent to a peer in a different branch office. The peer then uses the same key to decrypt the message. Which of the following describes this example?',
      answerOptions: [
        { answerText: 'Symmetric', isCorrect: true },
        { answerText: 'Asymmetric', isCorrect: false },
        { answerText: 'Hashing', isCorrect: false },
        { answerText: 'Salting', isCorrect: false },
      ],
    explanation: 'Symmetric Encryption In this type of encryption, there is only one key, and all parties involved use the same key to encrypt and decrypt information.'
  },
    {
      questionText: "A visitor plugs a laptop into a network jack in the lobby and is able to connect to the company's network. Which of the following should be configured on the existing network infrastructure to best prevent this activity?",
      answerOptions: [
        { answerText: 'Port security', isCorrect: true },
        { answerText: 'Web application firewall', isCorrect: false },
        { answerText: 'Transport layer security', isCorrect: false },
        { answerText: 'Virtual private network', isCorrect: false },
      ],
    explanation: 'Port security is a feature available on network switches that helps secure access to the physical network by restricting which devices can connect to each network port based on their MAC address.'
  },
    {
      questionText: "A security administrator is reissuing a former employee's laptop. Which of the following is the best combination of data handling activities for the administrator to perform? (Choose two.)",
      answerOptions: [
        { answerText: 'Data retention', isCorrect: false },
        { answerText: 'Certification', isCorrect: true },
        { answerText: 'Destruction', isCorrect: false },
        { answerText: 'Classification', isCorrect: false },
        { answerText: 'Sanitization', isCorrect: true },
        { answerText: 'Enumeration', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'A systems administrator would like to deploy a change to a production system. Which of the following must the administrator submit to demonstrate that the system can be restored to a working state in the event of a performance issue?',
      answerOptions: [
        { answerText: 'Backout plan', isCorrect: true },
        { answerText: 'Impact analysis', isCorrect: false },
        { answerText: 'Test procedure', isCorrect: false },
        { answerText: 'Approval procedure', isCorrect: false },
      ],
    explanation: 'What is a backout plan? A backout plan is a predefined strategy to reverse and recover from changes made to a system if the changes produce undesirable results. It\'s a safety measure that ensures data integrity and system availability. See also: backup, recovery time objective, mean time to recovery.'
  },
    {
      questionText: 'A company is redesigning its infrastructure and wants to reduce the number of physical servers in use. Which of the following architectures is best suited for this goal?',
      answerOptions: [
        { answerText: 'Serverless', isCorrect: false },
        { answerText: 'Segmentation', isCorrect: false },
        { answerText: 'Virtualization', isCorrect: true },
        { answerText: 'Microservices', isCorrect: false },
      ],
    explanation: 'Virtualization allows multiple virtual machines (VMs) to run on a single physical server, reducing the number of physical servers needed. This approach maximizes resource utilization, simplifies management, and lowers costs while providing flexibility to scale and isolate workloads as needed'
  },
    {
      questionText: "A bank set up a new server that contains customers' PII. Which of the following should the bank use to make sure the sensitive data is not modified?",
      answerOptions: [
        { answerText: 'Full disk encryption', isCorrect: false },
        { answerText: 'Network access control', isCorrect: false },
        { answerText: 'File integrity monitoring', isCorrect: true },
        { answerText: 'User behavior analytics', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'Users at a company are reporting they are unable to access the URL for a new retail website because it is flagged as gambling and is being blocked. Which of the following changes would allow users to access the site?',
      answerOptions: [
        { answerText: 'Creating a firewall rule to allow HTTPS traffic', isCorrect: false },
        { answerText: 'Configuring the IPS to allow shopping', isCorrect: false },
        { answerText: 'Tuning the DLP rule that detects credit card data', isCorrect: false },
        { answerText: 'Updating the categorization in the content filter', isCorrect: true },
      ],
    explanation: 'Updating the categorization in the content filter is the correct answer because it directly addresses the misclassification of the retail website as a gambling site. By correcting the categorization, users will be able to access the site without further issues, resolving the problem efficiently and effectively.'
  },
    {
      questionText: "Which of the following most impacts an administrator's ability to address CVEs discovered on a server?",
      answerOptions: [
        { answerText: 'Rescanning requirements', isCorrect: false },
        { answerText: 'Patch availability', isCorrect: true },
        { answerText: 'Organizational impact', isCorrect: false },
        { answerText: 'Risk tolerance', isCorrect: false },
      ],
    explanation: 'Patch availability most impacts an administrator\'s ability to address Common Vulnerabilities and Exposures (CVEs) discovered on a server. If patches are not available to fix the vulnerabilities, the administrator cannot remediate the issues, regardless of other factors.'
  },
    {
      questionText: 'Which of the following describes effective change management procedures?',
      answerOptions: [
        { answerText: 'Approving the change after a successful deployment', isCorrect: false },
        { answerText: 'Having a backout plan when a patch fails', isCorrect: true },
        { answerText: 'Using a spreadsheet for tracking changes', isCorrect: false },
        { answerText: 'Using an automatic change control bypass for security updates', isCorrect: false },
      ],
    explanation: 'o When applying patches or making system changes, there\'s always a risk of unforeseen issues. An effective backout plan allows for a quick and organized response, ensuring that systems can be returned to their last known good state, thereby maintaining business continuity and reducing the potential impact on operations.'
  },
    {
      questionText: 'The CIRT is reviewing an incident that involved a human resources recruiter exfiltrating sensitive company data. The CIRT found that the recruiter was able to use HTTP over port 53 to upload documents to a web server. Which of the following security infrastructure devices could have identified and blocked this activity?',
      answerOptions: [
        { answerText: 'WAF utilizing SSL decryption', isCorrect: false },
        { answerText: 'NGFW utilizing application inspection', isCorrect: true },
        { answerText: 'UTM utilizing a threat feed', isCorrect: false },
        { answerText: 'SD-WAN utilizing IPSec', isCorrect: false },
      ],
    explanation: 'NGFW utilizing application inspection is the correct answer because it provides the necessary application-level awareness to detect and block HTTP traffic over non-standard ports, such as port 53. The NGFW\'s advanced inspection capabilities allow it to enforce security policies that prevent unauthorized data exfiltration, making it an essential component of modern network security infrastructure.'
  },
    {
      questionText: 'An enterprise is working with a third party and needs to allow access between the internal networks of both parties for a secure file migration. The solution needs to ensure encryption is applied to all traffic that is traversing the networks. Which of the following solutions should most likely be implemented?',
      answerOptions: [
        { answerText: 'EAP', isCorrect: false },
        { answerText: 'IPSec', isCorrect: true },
        { answerText: 'SD-WAN', isCorrect: false },
        { answerText: 'TLS', isCorrect: false },
      ],
    explanation: 'If you need to secure communication between networks or remote sites, IPsec is a suitable choice. On the other hand, if you are primarily concerned with securing web-based communication, TLS is the preferred option.'
  },
    {
      questionText: "An administrator has identified and fingerprinted specific files that will generate an alert if an attempt is made to email these files outside of the organization. Which of the following best describes the tool the administrator is using?",
      answerOptions: [
        { answerText: 'DLP', isCorrect: true },
        { answerText: 'SNMP traps', isCorrect: false },
        { answerText: 'SCAP', isCorrect: false },
        { answerText: 'IPS', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: "A software developer released a new application and is distributing application files via the developer's website. Which of the following should the developer post on the website to allow users to verify the integrity of the downloaded files?",
      answerOptions: [
        { answerText: 'Hashes', isCorrect: true },
        { answerText: 'Certificates', isCorrect: false },
        { answerText: 'Algorithms', isCorrect: false },
        { answerText: 'Salting', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: "An organization wants to limit potential impact to its log-in database in the event of a breach. Which of the following options is the security team most likely to recommend?",
      answerOptions: [
        { answerText: 'Tokenization', isCorrect: false },
        { answerText: 'Hashing', isCorrect: true },
        { answerText: 'Obfuscation', isCorrect: false },
        { answerText: 'Segmentation', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: "An administrator finds that all user workstations and servers are displaying a message that is associated with files containing an extension of .ryk. Which of the following types of infections is present on the systems?",
      answerOptions: [
        { answerText: 'Virus', isCorrect: false },
        { answerText: 'Trojan', isCorrect: false },
        { answerText: 'Spyware', isCorrect: false },
        { answerText: 'Ransomware', isCorrect: true },
      ],
    explanation: ''
  },
    {
      questionText: 'A systems administrator is advised that an external web server is not functioning property. The administrator reviews the following firewall logs containing traffic going to the web server:Which of the following attacks is likely occurring?',
      answerOptions: [
        { answerText: 'DDoS', isCorrect: true },
        { answerText: 'Directory traversal', isCorrect: false },
        { answerText: 'Brute-force', isCorrect: false },
        { answerText: 'HTTPS downgrade', isCorrect: false },
      ],
    explanation: '(100.50.20.7) on port 443. This pattern is typical of a SYN flood DDoS attack, where attackers overwhelm a server with SYN requests to deplete its resources. Simultaneous Connections: All requests occur simultaneously (01:45:09.102), suggesting a coordinated attack, which is a hallmark of DDoS attacks. DDoS is the correct answer because the logs display multiple SYN requests from different IP addresses to the same server in a short time, indicative of a SYN flood DDoS attack aimed at overwhelming the server and causing disruption.'
  },
    {
      questionText: 'An organization would like to calculate the time needed to resolve a hardware issue with a server. Which of the following risk management processes describes this example?',
      answerOptions: [
        { answerText: 'Recovery point objective', isCorrect: false },
        { answerText: 'Mean time between failures', isCorrect: false },
        { answerText: 'Recovery time objective', isCorrect: false },
        { answerText: 'Mean time to repair', isCorrect: true },
      ],
    explanation: 'Mean Time to Repair (MTTR) is the correct answer because it directly relates to calculating the time needed to resolve hardware issues and restore the server to full functionality. MTTR is a critical metric for understanding and improving maintenance processes, ensuring efficient recovery from hardware failures.'
  },
    {
      questionText: 'A security engineer is installing an IPS to block signature-based attacks in the environment.Which of the following modes will best accomplish this task?',
      answerOptions: [
        { answerText: 'Monitor', isCorrect: false },
        { answerText: 'Sensor', isCorrect: false },
        { answerText: 'Audit', isCorrect: false },
        { answerText: 'Active', isCorrect: true },
      ],
    explanation: 'D. Active In active mode, an intrusion prevention system not only monitors network traffic for suspicious activity but also take immediate action to block or mitigate detected threats based on its signatures. This proactive approach ensures that identified threats are automatically blocked or neutralized providing a real-time protection for the environment.'
  },
    {
      questionText: 'An IT manager is increasing the security capabilities of an organization after a data classification initiative determined that sensitive data could be exfiltrated from the environment. Which of the following solutions would mitigate the risk?',
      answerOptions: [
        { answerText: 'XDR', isCorrect: false },
        { answerText: 'SPF', isCorrect: false },
        { answerText: 'DLP', isCorrect: true },
        { answerText: 'DMARC', isCorrect: false },
      ],
    explanation: 'C for sure'
  },
    {
      questionText: 'Which of the following is used to protect a computer from viruses, malware, and Trojans being installed and moving laterally across the network?',
      answerOptions: [
        { answerText: 'IDS', isCorrect: false },
        { answerText: 'ACL', isCorrect: false },
        { answerText: 'EDR', isCorrect: true },
        { answerText: 'NAC', isCorrect: false },
      ],
    explanation: 'IDS - Intrusion Detection System ACL - Access Control List EDR - Endpoint Detection and Response NAC - Network Access Control'
  },
    {
      questionText: 'Client files can only be accessed by employees who need to know the information and have specified roles in the company. Which of the following best describes this security concept?',
      answerOptions: [
        { answerText: 'Availability', isCorrect: false },
        { answerText: 'Confidentiality', isCorrect: true },
        { answerText: 'Integrity', isCorrect: false },
        { answerText: 'Non-repudiation', isCorrect: false },
      ],
    explanation: 'B. Confidentiality is the security concept that ensures client files are only accessible to employees who need to know the information and have specified roles in the company. It focuses on protecting information from unauthorized access and ensuring that only those with proper authorization can view or handle the data.'
  },
    {
      questionText: 'Which of the following describes the category of data that is most impacted when it is lost?',
      answerOptions: [
        { answerText: 'Confidential', isCorrect: false },
        { answerText: 'Public', isCorrect: false },
        { answerText: 'Private', isCorrect: false },
        { answerText: 'Critical', isCorrect: true },
      ],
    explanation: 'A. Confidential: Confidential data refers to information that is intended to be kept private within an organization or a specific group of individuals. Losing confidential data can have serious consequences, including reputational damage, financial losses, legal penalties, and regulatory violations. This is because confidential data often includes sensitive business information, trade secrets, personal identifiable information (PII), and other critical elements that could cause significant harm if exposed or lost. Why not D. Critical: Critical data refers to information necessary for the operation of a business or system. While critical data loss can be very disruptive, "confidential" is typically the term used for the most sensitive information, making it the category most directly impacted when lost.'
  },
    {
      questionText: 'A new employee logs in to the email system for the first time and notices a message from human resources about onboarding. The employee hovers over a few of the links within the email and discovers that the links do not correspond to links associated with the company. Which of the following attack vectors is most likely being used?',
      answerOptions: [
        { answerText: 'Business email', isCorrect: false },
        { answerText: 'Social engineering', isCorrect: true },
        { answerText: 'Unsecured network', isCorrect: false },
        { answerText: 'Default credentials', isCorrect: false },
      ],
    explanation: 'Business email compromise (BEC) is an email-based social engineering attack Social engineering refers to all the techniques used to coerce or talk a victim into revealing information that someone can use to perform malicious activities and render an organization or individual vulnerable to further attacks Answer: A- Business email'
  },
    {
      questionText: 'Which of the following describes the understanding between a company and a client about what will be provided and the accepted time needed to provide the company with the resources?',
      answerOptions: [
        { answerText: 'SLA', isCorrect: true },
        { answerText: 'MOU', isCorrect: false },
        { answerText: 'MOA', isCorrect: false },
        { answerText: 'BPA', isCorrect: false },
      ],
    explanation: 'MOU because it "describes the understanding". The question doesn\'t really ask for a formal document about expected levels of service.'
  },
    {
      questionText: 'A company that is located in an area prone to hurricanes is developing a disaster recovery plan and looking at site considerations that allow the company to immediately continue operations. Which of the following is the best type of site for this company?',
      answerOptions: [
        { answerText: 'Cold', isCorrect: false },
        { answerText: 'Tertiary', isCorrect: false },
        { answerText: 'Warm', isCorrect: false },
        { answerText: 'Hot', isCorrect: true },
      ],
    explanation: 'D is the answer but the wording is misleading here because, after they mentioned hurricanes, I initially thought they were asking about what climate to geolocate the new center.'
  },
    {
      questionText: 'Which of the following security controls is most likely being used when a critical legacy server is segmented into a private network?',
      answerOptions: [
        { answerText: 'Deterrent', isCorrect: false },
        { answerText: 'Corrective', isCorrect: false },
        { answerText: 'Compensating', isCorrect: true },
        { answerText: 'Preventive', isCorrect: false },
      ],
    explanation: 'C, compensating.'
  },
    {
      questionText: 'Which of the following best describes the practice of researching laws and regulations related to information security operations within a specific industry?',
      answerOptions: [
        { answerText: 'Compliance reporting', isCorrect: false },
        { answerText: 'GDPR', isCorrect: false },
        { answerText: 'Due diligence', isCorrect: true },
        { answerText: 'Attestation', isCorrect: false },
      ],
    explanation: 'C is correct'
  },
    {
      questionText: 'Which of the following considerations is the most important for an organization to evaluate as it establishes and maintains a data privacy program?',
      answerOptions: [
        { answerText: 'Reporting structure for the data privacy officer', isCorrect: false },
        { answerText: 'Request process for data subject access', isCorrect: false },
        { answerText: 'Role as controller or processor', isCorrect: true },
        { answerText: 'Physical location of the company', isCorrect: false },
      ],
    explanation: 'Between the two options, C. Role as controller or processor remains the most important consideration. This distinction fundamentally shapes the organization’s responsibilities and compliance requirements under data protection laws. However, the request process for data subject access is also crucial, as it directly impacts how the organization responds to individuals’ rights regarding their personal data. Both aspects are important, but understanding the role as a controller or processor is foundational.'
  },
    {
      questionText: 'A security analyst is investigating a workstation that is suspected of outbound communication to a command-and-control server. During the investigation, the analyst discovered that logs on the endpoint were deleted. Which of the following logs would the analyst most likely look at next?',
      answerOptions: [
        { answerText: 'IPS', isCorrect: false },
        { answerText: 'Firewall', isCorrect: true },
        { answerText: 'AСL', isCorrect: false },
        { answerText: 'Windows security', isCorrect: false },
      ],
    explanation: 'Since the logs on the endpoint were deleted, the security analyst would likely turn to firewall logs. Firewall logs can provide information about network traffic, including outbound connections that may indicate communication with a command-and-control server. These logs can help the analyst identify suspicious traffic patterns or unauthorized communication that bypassed endpoint defenses.'
  },
    {
      questionText: 'An IT manager is putting together a documented plan describing how the organization will keep operating in the event of a global incident. Which of the following plans is the IT manager creating?',
      answerOptions: [
        { answerText: 'Business continuity', isCorrect: true },
        { answerText: 'Physical security', isCorrect: false },
        { answerText: 'Change management', isCorrect: false },
        { answerText: 'Disaster recovery', isCorrect: false },
      ],
    explanation: 'A business continuity plan describes how an organization will maintain its operations and continue functioning in the event of a significant disruption or global incident. It covers strategies for ensuring that critical business functions remain operational despite various types of emergencies or disasters. therefore the answer is A.'
  },
    {
      questionText: 'A business needs a recovery site but does not require immediate failover. The business also wants to reduce the workload required to recover from an outage. Which of the following recovery sites is the best option?',
      answerOptions: [
        { answerText: 'Hot', isCorrect: false },
        { answerText: 'Cold', isCorrect: false },
        { answerText: 'Warm', isCorrect: true },
        { answerText: 'Geographically dispersed', isCorrect: false },
      ],
    explanation: 'c. warm'
  },
    {
      questionText: "A security team is setting up a new environment for hosting the organization's on-premises software application as a cloud-based service. Which of the following should the team ensure is in place in order for the organization to follow security best practices?",
      answerOptions: [
        { answerText: 'Virtualization and isolation of resources', isCorrect: true },
        { answerText: 'Network segmentation', isCorrect: false },
        { answerText: 'Data encryption', isCorrect: false },
        { answerText: 'Strong authentication policies', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: "A manager receives an email that contains a link to receive a refund. After hovering over the link, the manager notices that the domain's URL points to a suspicious link. Which of the following security practices helped the manager to identify the attack?",
      answerOptions: [
        { answerText: 'End user training', isCorrect: true },
        { answerText: 'Policy review', isCorrect: false },
        { answerText: 'URL scanning', isCorrect: false },
        { answerText: 'Plain text email', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'A company wants to verify that the software the company is deploying came from the vendor the company purchased the software from. Which of the following is the best way for the company to confirm this information?',
      answerOptions: [
        { answerText: 'Validate the code signature.', isCorrect: true },
        { answerText: 'Execute the code in a sandbox.', isCorrect: false },
        { answerText: 'Search the executable for ASCII strings.', isCorrect: false },
        { answerText: 'Generate a hash of the files.', isCorrect: false },
      ],
    explanation: 'A. Validate the code signature Code signing is a process where the software vendor signs the executable code with a digital certificate. This certificate verifies the identity of the software vendor and ensures that the code has not been altered with since it was signed. By validating the code signature, the company can confirm the authenticity and integrity of the software.'
  },
    {
      questionText: 'A systems administrator notices that one of the systems critical for processing customer transactions is running an end-of-life operating system. Which of the following techniques would increase enterprise security?',
      answerOptions: [
        { answerText: 'Installing HIDS on the system', isCorrect: false },
        { answerText: 'Placing the system in an isolated VLAN', isCorrect: true },
        { answerText: 'Decommissioning the system', isCorrect: false },
        { answerText: 'Encrypting the system\'s hard drive', isCorrect: false },
      ],
    explanation: 'B. Placing the system in an isolated VLAN Give that the system is critical for processing customer transactions, decommissioning immediately might impact business continuity. The next best approach is to place the system in an isolated VLAN.'
  },
    {
      questionText: "The Chief Information Security Officer (CISO) at a large company would like to gain an understanding of how the company's security policies compare to the requirements imposed by external regulators. Which of the following should the CISO use?",
      answerOptions: [
        { answerText: 'Penetration test', isCorrect: false },
        { answerText: 'Internal audit', isCorrect: true },
        { answerText: 'Attestation', isCorrect: false },
        { answerText: 'External examination', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: "A systems administrator notices that the research and development department is not using the company VPN when accessing various company-related services and systems. Which of the following scenarios describes this activity?",
      answerOptions: [
        { answerText: 'Espionage', isCorrect: false },
        { answerText: 'Data exfiltration', isCorrect: false },
        { answerText: 'Nation-state attack', isCorrect: false },
        { answerText: 'Shadow IT', isCorrect: true },
      ],
    explanation: ''
  },
    {
      questionText: "The marketing department set up its own project management software without telling the appropriate departments. Which of the following describes this scenario?",
      answerOptions: [
        { answerText: 'Shadow IT', isCorrect: true },
        { answerText: 'Insider threat', isCorrect: false },
        { answerText: 'Data exfiltration', isCorrect: false },
        { answerText: 'Service disruption', isCorrect: false },
      ],
    explanation: 'Shadow IT is when an employee uses information technology (IT) systems without the approval of an organization\'s IT department.'
  },
    {
      questionText: 'Which of the following would best explain why a security analyst is running daily vulnerability scans on all corporate endpoints?',
      answerOptions: [
        { answerText: 'To track the status of patching installations', isCorrect: true },
        { answerText: 'To find shadow IT cloud deployments', isCorrect: false },
        { answerText: 'To continuously the monitor hardware inventory', isCorrect: false },
        { answerText: 'To hunt for active attackers in the network', isCorrect: false },
      ],
    explanation: 'Answer A is correct: Daily vulnerability scans help ensure that all the endpoints are up to date with security patches and identify any vulnerabilities that may have been introduced due to unpatched software. This regular scanning helps in monitoring and verifying the effectiveness of patch management process.'
  },
    {
      questionText: 'Which of the following is classified as high availability in a cloud environment?',
      answerOptions: [
        { answerText: 'Access broker', isCorrect: false },
        { answerText: 'Cloud HSM', isCorrect: false },
        { answerText: 'WAF', isCorrect: false },
        { answerText: 'Load balancer', isCorrect: true },
      ],
    explanation: 'D Load balancer distributes incoming network traffic across multiple servers or instances ensuring that no single server becomes overwhelmed and helps maintain the availability of applications and services.'
  },
    {
      questionText: 'Which of the following security measures is required when using a cloud-based platform for IoT management?',
      answerOptions: [
        { answerText: 'Encrypted connection', isCorrect: true },
        { answerText: 'Federated identity', isCorrect: false },
        { answerText: 'Firewall', isCorrect: false },
        { answerText: 'Single sign-on', isCorrect: false },
      ],
    explanation: 'A IOT devices often transmit sensitive data over networks and encryption ensures that this data is securely transmitted and protected from interception or tampering.'
  },
    {
      questionText: 'Which of the following threat vectors is most commonly utilized by insider threat actors attempting data exfiltration?',
      answerOptions: [
        { answerText: 'Unidentified removable devices', isCorrect: true },
        { answerText: 'Default network device credentials', isCorrect: false },
        { answerText: 'Spear phishing emails', isCorrect: false },
        { answerText: 'Impersonation of business units through typosquatting', isCorrect: false },
      ],
    explanation: 'A. GPT'
  },
    {
      questionText: 'Which of the following methods to secure credit card data is best to use when a requirement is to see only the last four numbers on a credit card?',
      answerOptions: [
        { answerText: 'Encryption', isCorrect: false },
        { answerText: 'Hashing', isCorrect: false },
        { answerText: 'Masking', isCorrect: true },
        { answerText: 'Tokenization', isCorrect: false },
      ],
    explanation: 'Masking involves hiding sensitive information by replacing it with a specific character, such as an asterisk (*). In the case of credit card numbers, masking would typically involve displaying only the last four digits, while the rest of the numbers are replaced with asterisks. This allows for partial visibility of the card number while protecting the sensitive information.'
  },
    {
      questionText: 'The Chief Information Security Officer (CISO) has determined the company is non-compliant with local data privacy regulations. The CISO needs to justify the budget request for more resources. Which of the following should the CISO present to the board as the direct consequence of non-compliance?',
      answerOptions: [
        { answerText: 'Fines', isCorrect: true },
        { answerText: 'Reputational damage', isCorrect: false },
        { answerText: 'Sanctions', isCorrect: false },
        { answerText: 'Contractual implications', isCorrect: false },
      ],
    explanation: 'Why not e: "All to Above" jajajaj'
  },
    {
      questionText: 'Which of the following alert types is the most likely to be ignored over time?',
      answerOptions: [
        { answerText: 'True positive', isCorrect: false },
        { answerText: 'True negative', isCorrect: false },
        { answerText: 'False positive', isCorrect: true },
        { answerText: 'False negative', isCorrect: false },
      ],
    explanation: 'C. False Positive - triggered when an event is NOT actually a threat. True Positive - an actual threat True Negative - no threat False Negative - an actual threat isn\'t detected, dangerous type since threats go unnoticed.'
  },
    {
      questionText: 'A security analyst is investigating an application server and discovers that software on the server is behaving abnormally. The software normally runs batch jobs locally and does not generate traffic, but the process is now generating outbound traffic over random high ports. Which of the following vulnerabilities has likely been exploited in this software?',
      answerOptions: [
        { answerText: 'Memory injection', isCorrect: true },
        { answerText: 'Race condition', isCorrect: false },
        { answerText: 'Side loading', isCorrect: false },
        { answerText: 'SQL injection', isCorrect: false },
      ],
    explanation: 'A is correct. Memory injection allows the attackers to inject malicious code directly into the memory of a running process which can then be used to execute arbitrary commands or generate unauthorized network traffic. Race Condition refers to two processes competing to modify the same resource which can lead to unpredictable behavior but is less likely to cause abnormal outbound traffic. Side Loading refers to loading a malicious DLL into a legitimate process. SQL injection involves injecting malicious SQL code into a database and is primarily concerned with database manipulation rather than generating outbound network traffic.'
  },
    {
      questionText: 'An important patch for a critical application has just been released, and a systems administrator is identifying all of the systems requiring the patch. Which of the following must be maintained in order to ensure that all systems requiring the patch are updated?',
      answerOptions: [
        { answerText: 'Asset inventory', isCorrect: true },
        { answerText: 'Network enumeration', isCorrect: false },
        { answerText: 'Data certification', isCorrect: false },
        { answerText: 'Procurement process', isCorrect: false },
      ],
    explanation: 'The best answer is: A. Asset inventory An asset inventory is essential for ensuring that all systems requiring the patch are updated. By maintaining a comprehensive inventory of all systems, the administrator can identify which devices have the critical application installed and require the patch. An accurate asset inventory helps ensure that no systems are overlooked during the patching process. - Network enumeration focuses on identifying devices on the network but does not necessarily provide information about the applications running on those devices. - Data certification relates to validating the integrity and accuracy of data, which is unrelated to identifying systems needing patches. - Procurement process involves acquiring hardware or software but does not help track existing systems for patching needs. Therefore, an asset inventory is the best choice for maintaining awareness of all systems that require patching.'
  },
    {
      questionText: 'Which of the following should a security operations center use to improve its incident response procedure?',
      answerOptions: [
        { answerText: 'Playbooks', isCorrect: true },
        { answerText: 'Frameworks', isCorrect: false },
        { answerText: 'Baselines', isCorrect: false },
        { answerText: 'Benchmarks', isCorrect: false },
      ],
    explanation: 'A. Playbooks Its a step by step procedure outlining how to respond to specific types of incidents.'
  },
    {
      questionText: "Which of the following describes an executive team that is meeting in a board room and testing the company's incident response plan?",
      answerOptions: [
        { answerText: 'Continuity of operations', isCorrect: false },
        { answerText: 'Capacity planning', isCorrect: false },
        { answerText: 'Tabletop exercise', isCorrect: true },
        { answerText: 'Parallel processing', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'A healthcare organization wants to provide a web application that allows individuals to digitally report health emergencies. Which of the following is the most important consideration during development?',
      answerOptions: [
        { answerText: 'Scalability', isCorrect: false },
        { answerText: 'Availability', isCorrect: true },
        { answerText: 'Cost', isCorrect: false },
        { answerText: 'Ease of deployment', isCorrect: false },
      ],
    explanation: 'to report report health emergencies...'
  },
    {
      questionText: 'Which of the following agreement types defines the time frame in which a vendor needs to respond?',
      answerOptions: [
        { answerText: 'SOW', isCorrect: false },
        { answerText: 'SLA', isCorrect: true },
        { answerText: 'MOA', isCorrect: false },
        { answerText: 'MOU', isCorrect: false },
      ],
    explanation: 'SOW - Statement of Work SLA - Service Level Agreement MOA - Memorandum of Agreement MOU - Memorandum of Understanding'
  },
    {
      questionText: 'Which of the following is a feature of a next-generation SIEM system?',
      answerOptions: [
        { answerText: 'Virus signatures', isCorrect: false },
        { answerText: 'Automated response actions', isCorrect: true },
        { answerText: 'Security agent deployment', isCorrect: false },
        { answerText: 'Vulnerability scanning', isCorrect: false },
      ],
    explanation: 'next-gen SIEM platforms can dynamically analyze vast datasets in real time, enabling the identification of subtle, evolving threats that traditional systems might overlook.'
  },
    {
      questionText: 'To improve the security at a data center, a security administrator implements a CCTV system and posts several signs about the possibility of being filmed. Which of the following best describe these types of controls? (Choose two.)',
      answerOptions: [
        { answerText: 'Preventive', isCorrect: false },
        { answerText: 'Deterrent', isCorrect: true },
        { answerText: 'Corrective', isCorrect: false },
        { answerText: 'Directive', isCorrect: false },
        { answerText: 'Compensating', isCorrect: false },
        { answerText: 'Detective', isCorrect: true },
      ],
    explanation: 'I believe it is B and F because the CCTV will give you the ability to monitor the data center and its presence and signs are a deterrent.'
  },
    {
      questionText: 'Which of the following examples would be best mitigated by input sanitization?',
      answerOptions: [
        { answerText: "A. <script>alert('XSS')</script>", isCorrect: true },
        { answerText: 'B.nmap - 10.11.1.130', isCorrect: false },
        { answerText: 'C.Email message: "Click this link to get your free gift card."', isCorrect: false },
        { answerText: 'D.Browser message: "Your connection is not private."', isCorrect: false },
      ],
    explanation: 'This question is the same on exam topics 601 #604 - The answer is in fact A and it shows "A. <script>alert("Warning!");</script>"'
  },
    {
      questionText: 'An attacker posing as the Chief Executive Officer calls an employee and instructs the employee to buy gift cards. Which of the following techniques is the attacker using?',
      answerOptions: [
        { answerText: 'Smishing', isCorrect: false },
        { answerText: 'Disinformation', isCorrect: false },
        { answerText: 'Impersonating', isCorrect: true },
        { answerText: 'Whaling', isCorrect: false },
      ],
    explanation: 'Impersonating involves pretending to be someone else, in this case, the Chief Executive Officer (CEO), to deceive the employee into taking a specific action (buying gift cards). The attacker is leveraging the authority and trust associated with the CEO\'s position to manipulate the employee. Whaling: This phishing attack targets high-profile individuals, such as executives. An attacker is \'posing\' and not \'targeting\' a CEO. Therefore its C'
  },
    {
      questionText: 'After conducting a vulnerability scan, a systems administrator notices that one of the identified vulnerabilities is not present on the systems that were scanned. Which of the following describes this example?',
      answerOptions: [
        { answerText: 'False positive', isCorrect: true },
        { answerText: 'False negative', isCorrect: false },
        { answerText: 'True positive', isCorrect: false },
        { answerText: 'True negative', isCorrect: false },
      ],
    explanation: 'the vulnerability was NOT present after the scan indicates a false positive'
  },
    {
      questionText: 'A recent penetration test identified that an attacker could flood the MAC address table of network switches. Which of the following would best mitigate this type of attack?',
      answerOptions: [
        { answerText: 'Load balancer', isCorrect: false },
        { answerText: 'Port security', isCorrect: true },
        { answerText: 'IPS', isCorrect: false },
        { answerText: 'NGFW', isCorrect: false },
      ],
    explanation: 'Port security is a feature on network switches that allows you to limit the number of MAC addresses that can be learned on a specific port. If the limit is exceeded, the switch can take predefined actions such as shutting down the port, restricting traffic, or generating alerts. This effectively prevents attackers from overwhelming the switch with a large number of MAC addresses, which could otherwise cause the switch to behave like a hub, sending traffic to all ports and potentially exposing sensitive data. (B)'
  },
    {
      questionText: "A user would like to install software and features that are not available with a smartphone's default software. Which of the following would allow the user to install unauthorized software and enable new features?",
      answerOptions: [
        { answerText: 'SQLi', isCorrect: false },
        { answerText: 'Cross-site scripting', isCorrect: false },
        { answerText: 'Jailbreaking', isCorrect: true },
        { answerText: 'Side loading', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'Which of the following phases of an incident response involves generating reports?',
      answerOptions: [
        { answerText: 'Recovery', isCorrect: false },
        { answerText: 'Preparation', isCorrect: false },
        { answerText: 'Lessons learned', isCorrect: true },
        { answerText: 'Containment', isCorrect: false },
      ],
    explanation: 'C. Lessons Learned - focused on documentation and learning from the incident to improve future responses.'
  },
    {
      questionText: 'Which of the following methods would most likely be used to identify legacy systems?',
      answerOptions: [
        { answerText: 'Bug bounty program', isCorrect: false },
        { answerText: 'Vulnerability scan', isCorrect: true },
        { answerText: 'Package monitoring', isCorrect: false },
        { answerText: 'Dynamic analysis', isCorrect: false },
      ],
    explanation: 'The method most likely used to identify legacy systems is: B. Vulnerability scan. A vulnerability scan assesses systems for known vulnerabilities, outdated software versions, and unsupported systems. This makes it an effective way to identify legacy systems that may no longer be receiving security updates or support. A. Bug bounty program: This focuses on crowdsourcing the identification of specific vulnerabilities but is not primarily aimed at identifying legacy systems. C. Package monitoring: Tracks software packages for updates, but it doesn\'t specifically target legacy systems. D. Dynamic analysis: Involves testing software during runtime for vulnerabilities but is not typically used to identify legacy systems. A vulnerability scan is the most effective approach for identifying legacy systems in an environment'
  },
    {
      questionText: 'Employees located off-site must have access to company resources in order to complete their assigned tasks. These employees utilize a solution that allows remote access without interception concerns. Which of the following best describes this solution?',
      answerOptions: [
        { answerText: 'Proxy server', isCorrect: false },
        { answerText: 'NGFW', isCorrect: false },
        { answerText: 'VPN', isCorrect: true },
        { answerText: 'Security zone', isCorrect: false },
      ],
    explanation: 'C. VPN - provides secure remote access assuring data transmitted between remote employees and company resources is encrypted and protected from interception.'
  },
    {
      questionText: 'A company allows customers to upload PDF documents to its public e-commerce website. Which of the following would a security analyst most likely recommend?',
      answerOptions: [
        { answerText: 'Utilizing attack signatures in an IDS', isCorrect: false },
        { answerText: 'Enabling malware detection through a UTM', isCorrect: false },
        { answerText: 'Limiting the affected servers with a load balancer', isCorrect: false },
        { answerText: 'Blocking command injections via a WAF', isCorrect: true },
      ],
    explanation: 'B PDFs can be used to deliver malware such as embedded scripts or exploits. Enabling malware detection through a UTM helps to scan and block malicious content within uploaded files before they reach the server.'
  },
    {
      questionText: 'A security analyst developed a script to automate a trivial and repeatable task. Which of the following best describes the benefits of ensuring other team members understand how the script works?',
      answerOptions: [
        { answerText: 'To reduce implementation cost', isCorrect: false },
        { answerText: 'To identify complexity', isCorrect: false },
        { answerText: 'To remediate technical debt', isCorrect: false },
        { answerText: 'To prevent a single point of failure', isCorrect: true },
      ],
    explanation: 'NO GPT COMMENT!!!! HALLELUJAH!!!!!'
  },
    {
      questionText: 'A company is decommissioning its physical servers and replacing them with an architecture that will reduce the number of individual operating systems. Which of the following strategies should the company use to achieve this security requirement?',
      answerOptions: [
        { answerText: 'Microservices', isCorrect: false },
        { answerText: 'Containerization', isCorrect: true },
        { answerText: 'Virtualization', isCorrect: false },
        { answerText: 'Infrastructure as code', isCorrect: false },
      ],
    explanation: 'B Containerization allows multiple applications or services to run in isolated environments on the same underlying OS. Unlike, virtualization where each VM runs its own OS, containers share the host OS kernel but keep the applications isolated from one another. This significantly reduces the number of operating systems required while maintaining security and isolation between applications.'
  },
    {
      questionText: 'An administrator needs to perform server hardening before deployment. Which of the following steps should the administrator take? (Choose two.)',
      answerOptions: [
        { answerText: 'Disable default accounts.', isCorrect: true },
        { answerText: 'Add the server to the asset inventory.', isCorrect: false },
        { answerText: 'Remove unnecessary services.', isCorrect: true },
        { answerText: 'Document default passwords.', isCorrect: false },
        { answerText: 'Send server logs to the SIEM.', isCorrect: false },
        { answerText: 'Join the server to the corporate domain.', isCorrect: false },
      ],
    explanation: 'AC is correct. both actions make the server less vulnerable.'
  },
    {
      questionText: 'A Chief Information Security Officer would like to conduct frequent, detailed reviews of systems and procedures to track compliance objectives. Which of the following will be the best method to achieve this objective?',
      answerOptions: [
        { answerText: 'Third-party attestation', isCorrect: false },
        { answerText: 'Penetration testing', isCorrect: false },
        { answerText: 'Internal auditing', isCorrect: true },
        { answerText: 'Vulnerability scans', isCorrect: false },
      ],
    explanation: 'It\'s important to read and consider all adjectives contained in the questions. Here, a key word is frequent. A and B would not be done frequently. D would not capture all compliance objectives. Only C remains, and it covers stated objectives.'
  },
    {
      questionText: 'Which of the following security concepts is accomplished with the installation of a RADIUS server?',
      answerOptions: [
        { answerText: 'CIA', isCorrect: false },
        { answerText: 'AAA', isCorrect: true },
        { answerText: 'ACL', isCorrect: false },
        { answerText: 'PEM', isCorrect: false },
      ],
    explanation: 'B Other being a server, RADIUS is a networking protocol that provides centralized authentication, authorization and accounting for users who connect and use a network service.'
  },
    {
      questionText: 'After creating a contract for IT contractors, the human resources department changed several clauses. The contract has gone through three revisions. Which of the following processes should the human resources department follow to track revisions?',
      answerOptions: [
        { answerText: 'Version validation', isCorrect: false },
        { answerText: 'Version changes', isCorrect: false },
        { answerText: 'Version updates', isCorrect: false },
        { answerText: 'Version control', isCorrect: true },
      ],
    explanation: 'D. Version Control Version control involves maintaining a record of changes made to the document, including details such as who made the changes, when they were made, and what was modified. This process ensures that all revisions are documented, and the most current version of the contract is clearly identified.'
  },
    {
      questionText: 'The executive management team is mandating the company develop a disaster recovery plan. The cost must be kept to a minimum, and the money to fund additional internet connections is not available. Which of the following would be the best option?',
      answerOptions: [
        { answerText: 'Hot site', isCorrect: false },
        { answerText: 'Cold site', isCorrect: true },
        { answerText: 'Failover site', isCorrect: false },
        { answerText: 'Warm site', isCorrect: false },
      ],
    explanation: 'The lowest cost solution is a Cold Site.'
  },
    {
      questionText: 'An administrator at a small business notices an increase in support calls from employees who receive a blocked page message after trying to navigate to a spoofed website. Which of the following should the administrator do?',
      answerOptions: [
        { answerText: 'Deploy multifactor authentication.', isCorrect: false },
        { answerText: 'Decrease the level of the web filter settings.', isCorrect: false },
        { answerText: 'Implement security awareness training.', isCorrect: true },
        { answerText: 'Update the acceptable use policy.', isCorrect: false },
      ],
    explanation: 'C. Implement security awareness training. Explanation: The increase in blocked page messages indicates employees are attempting to visit spoofed or malicious websites, possibly due to phishing attempts. Security awareness training can educate employees on recognizing phishing attempts, spoofed websites, and other social engineering tactics to reduce the likelihood of future incidents. Other Options: A. Deploy multifactor authentication: While MFA is essential for account security, it does not address the issue of employees unknowingly attempting to access spoofed websites. B. Decrease the level of the web filter settings: This would make the organization more vulnerable to threats by allowing access to malicious sites. D. Update the acceptable use policy: Updating policies is good practice but won\'t directly address the root cause of employees falling for spoofed sites.'
  },
    {
      questionText: 'Which of the following teams is best suited to determine whether a company has systems that can be exploited by a potential, identified vulnerability?',
      answerOptions: [
        { answerText: 'Purple team', isCorrect: false },
        { answerText: 'Blue team', isCorrect: false },
        { answerText: 'Red team', isCorrect: true },
        { answerText: 'White team', isCorrect: false },
      ],
    explanation: 'The correct answer is: B. Blue team Explanation: The blue team is responsible for defending the organization\'s systems, monitoring for vulnerabilities, and ensuring that systems are secure against potential threats. They: Conduct vulnerability assessments to identify exploitable weaknesses. Evaluate the impact of identified vulnerabilities on the organization\'s systems. Work to mitigate risks and patch vulnerabilities.'
  },
    {
      questionText: 'A company is reviewing options to enforce user logins after several account takeovers. The following conditions must be met as part of the solution:\n\n• Allow employees to work remotely or from assigned offices around the world.\n• Provide a seamless login experience.\n• Limit the amount of equipment required.\n\n Which of the following best meets these conditions?',
      answerOptions: [
        { answerText: 'Trusted devices', isCorrect: true },
        { answerText: 'Geotagging', isCorrect: false },
        { answerText: 'Smart cards', isCorrect: false },
        { answerText: 'Time-based logins', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'Which of the following methods can be used to detect attackers who have successfully infiltrated a network? (Choose two.)',
      answerOptions: [
        { answerText: 'Tokenization', isCorrect: false },
        { answerText: 'CI/CD', isCorrect: false },
        { answerText: 'Honeypots', isCorrect: true },
        { answerText: 'Threat modeling', isCorrect: false },
        { answerText: 'DNS sinkhole', isCorrect: true },
        { answerText: 'Data obfuscation', isCorrect: false },
      ],
    explanation: 'C&E Honeypot attracts and traps attacker and DNS sinkhole redirects malicious domain name queries to a controlled server to detect and block communication between compromised host and their C2 servers.'
  },
    {
      questionText: 'A company wants to ensure that the software it develops will not be tampered with after the final version is completed. Which of the following should the company most likely use?',
      answerOptions: [
        { answerText: 'Hashing', isCorrect: true },
        { answerText: 'Encryption', isCorrect: false },
        { answerText: 'Baselines', isCorrect: false },
        { answerText: 'Tokenization', isCorrect: false },
      ],
    explanation: 'A. Hashing: Hashing is a technique used to generate a unique, fixed-size value (hash) based on the contents of a file, such as a software application. After the final version of the software is completed, the company can create a hash of the software file and store it securely. Whenever the software is accessed or distributed, the company can recalculate the hash and compare it to the original hash. If the hashes match, the file has not been tampered with. This provides a way to verify the integrity of the software and ensure that it has not been altered after the final version. Why not C. Baselines: Baselines refer to a set of standards or configurations for systems and software that are considered secure. While baselines can be useful for ensuring that systems meet security standards, they do not directly address ensuring that the software has not been tampered with after it is finalized. Baselines help with ongoing security practices rather than tamper detection.'
  },
    {
      questionText: 'An organization completed a project to deploy SSO across all business applications last year. Recently, the finance department selected a new cloud-based accounting software vendor. Which of the following should most likely be configured during the new software deployment?',
      answerOptions: [
        { answerText: 'RADIUS', isCorrect: false },
        { answerText: 'SAML', isCorrect: true },
        { answerText: 'EAP', isCorrect: false },
        { answerText: 'OpenID', isCorrect: false },
      ],
    explanation: 'B SAML is widely used protocol for enabling SSO across different applications and systems, particularly in enterprise environments. It allows users to authentication once and gain access to multiple application, including cloud based services. RADUIS is typically used for network access authentication and is not generally used for SSO with cloud based applications. EAP is used for network authentication protocols particularly in wireless networks and does not apply to SSO. OpenID is an identity layer on top of OAuth 2.0 for authentication but is less commonly used in enterprise environments compared to SAML for SSO.'
  },
    {
      questionText: "A user, who is waiting for a flight at an airport, logs in to the airline website using the public Wi-Fi, ignores a security warning and purchases an upgraded seat. When the flight lands, the user finds unauthorized credit card charges. Which of the following attacks most likely occurred?",
      answerOptions: [
        { answerText: 'Replay attack', isCorrect: false },
        { answerText: 'Memory leak', isCorrect: false },
        { answerText: 'Buffer overflow attack', isCorrect: false },
        { answerText: 'On-path attack', isCorrect: true },
      ],
    explanation: 'An on-path attack, also known as a man-in-the-middle (MITM) attack, occurs when an attacker intercepts the communication between two parties (in this case, the user and the airline\'s website). Since the user was on a public Wi-Fi network and ignored security warnings, it\'s possible that the attacker was able to intercept the credit card information during the transaction, leading to unauthorized charges.'
  },
    {
      questionText: 'A network engineer deployed a redundant switch stack to increase system availability. However, the budget can only cover the cost of one ISP connection. Which of the following best describes the potential risk factor?',
      answerOptions: [
        { answerText: 'The equipment MTBF is unknown.', isCorrect: false },
        { answerText: 'The ISP has no SLA.', isCorrect: false },
        { answerText: 'An RPO has not been determined.', isCorrect: false },
        { answerText: 'There is a single point of failure.', isCorrect: true },
      ],
    explanation: 'D Since the budget only allows for one ISP connection, this create a single point of failure for the network connectivity.'
  },
    {
      questionText: 'A network team segmented a critical, end-of-life server to a VLAN that can only be reached by specific devices but cannot be reached by the perimeter network. Which of the following best describe the controls the team implemented? (Choose two.)',
      answerOptions: [
        { answerText: 'Managerial', isCorrect: false },
        { answerText: 'Physical', isCorrect: false },
        { answerText: 'Corrective', isCorrect: false },
        { answerText: 'Detective', isCorrect: false },
        { answerText: 'Compensating', isCorrect: true },
        { answerText: 'Technical', isCorrect: true },
        { answerText: 'Deterrent', isCorrect: false },
      ],
    explanation: 'EF Technical controls involve the use of technology to manage or mitigate risks. By segmenting the server into VALN and restricting access to specific devices, the network team has employed a technical control here. Compensating controls are alternative measures in place to address a risk when the primary control is not feasible which in these case segmenting the server into VLAN and limiting access can be seen as compensating control.'
  },
    {
      questionText: 'A threat actor was able to use a username and password to log in to a stolen company mobile device. Which of the following provides the best solution to increase mobile data security on all employees\' company mobile devices?',
      answerOptions: [
        { answerText: 'Application management', isCorrect: false },
        { answerText: 'Full disk encryption', isCorrect: false },
        { answerText: 'Remote wipe', isCorrect: true },
        { answerText: 'Containerization', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'Which of the following best describes the risk present after controls and mitigating factors have been applied?',
      answerOptions: [
        { answerText: 'Residual', isCorrect: true },
        { answerText: 'Avoided', isCorrect: false },
        { answerText: 'Inherent', isCorrect: false },
        { answerText: 'Operational', isCorrect: false },
      ],
    explanation: 'A. Residual Rationale: Residual risk is the remaining risk after implementing security controls and mitigation strategies Represents the risk that persists even after applying protective measures Cannot be completely eliminated, only reduced to an acceptable level Reflects the potential impact and likelihood of a risk after implementing safeguards'
  },
    {
      questionText: 'A software development team asked a security administrator to recommend techniques that should be used to reduce the chances of the software being reverse engineered. Which of the following should the security administrator recommend?',
      answerOptions: [
        { answerText: 'Digitally signing the software', isCorrect: false },
        { answerText: 'Performing code obfuscation', isCorrect: true },
        { answerText: 'Limiting the use of third-party libraries', isCorrect: false },
        { answerText: 'Using compile flags', isCorrect: false },
      ],
    explanation: 'B Performing code obfuscation Code obfuscation deliberately makes the code more difficult to understand. This involves renaming variables, methods etc. Altering the code structure in ways that do not affect functionality but make reverse engineering much harder. Attacker use reverse engineering to find vulnerabilities that can be exploited or remove or bypass security protections such as encryption or anti tamper mechanisms.'
  },
    {
      questionText: 'Which of the following is a possible factor for MFA?',
      answerOptions: [
        { answerText: 'Something you exhibit', isCorrect: false },
        { answerText: 'Something you have', isCorrect: true },
        { answerText: 'Somewhere you are', isCorrect: false },
        { answerText: 'Someone you know', isCorrect: false },
      ],
    explanation: 'Very tricky with the the D option, which says "someone" instead of something you know, which will be the password option.'
  },
    {
      questionText: 'Easy-to-guess passwords led to an account compromise. The current password policy requires at least 12 alphanumeric characters, one uppercase character, one lowercase character, a password history of two passwords, a minimum password age of one day, and a maximum password age of 90 days. Which of the following would reduce the risk of this incident from happening again? (Choose two.)',
      answerOptions: [
        { answerText: 'Increasing the minimum password length to 14 characters.', isCorrect: true },
        { answerText: 'Upgrading the password hashing algorithm from MD5 to SHA-512.', isCorrect: false },
        { answerText: 'Increasing the maximum password age to 120 days.', isCorrect: false },
        { answerText: 'Reducing the minimum password length to ten characters.', isCorrect: false },
        { answerText: 'Reducing the minimum password age to zero days.', isCorrect: false },
        { answerText: 'Including a requirement for at least one special character.', isCorrect: true },
      ],
    explanation: 'Since the issue is with the passwords being easy to guess, the solution would be one that addresses password complexity (and not password history or age necessarily). Increasing the minimum length of the password and introducing a special character would be the best options for this.'
  },
    {
      questionText: "A user downloaded software from an online forum. After the user installed the software, the security team observed external network traffic connecting to the user's computer on an uncommon port. Which of the following is the most likely explanation of this unauthorized connection?",
      answerOptions: [
        { answerText: 'The software had a hidden keylogger.', isCorrect: false },
        { answerText: 'The software was ransomware.', isCorrect: false },
        { answerText: 'The user\'s computer had a fileless virus.', isCorrect: false },
        { answerText: 'The software contained a backdoor.', isCorrect: true },
      ],
    explanation: ''
  },
    {
      questionText: 'A utility company is designing a new platform that will host all the virtual machines used by business applications. The requirements include:\n\n•  A starting baseline of 50% memory utilization\n•  Storage scalability\n•  Single circuit failure resilience\n\n Which of the following best meets all of these requirements?',
      answerOptions: [
        { answerText: 'Connecting dual PDUs to redundant power supplies', isCorrect: false },
        { answerText: 'Transitioning the platform to an IaaS provider', isCorrect: true },
        { answerText: 'Configuring network load balancing for multiple paths', isCorrect: false },
        { answerText: 'Deploying multiple large NAS devices for each host', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'Which of the following best describes a use case for a DNS sinkhole?',
      answerOptions: [
        { answerText: "Attackers can see a DNS sinkhole as a highly valuable resource to identify a company's domain structure.", isCorrect: false },
        { answerText: 'A DNS sinkhole can be used to draw employees away from known-good websites to malicious ones owned by the attacker.', isCorrect: false },
        { answerText: 'A DNS sinkhole can be used to capture traffic to known-malicious domains used by attackers.', isCorrect: true },
        { answerText: "A DNS sinkhole can be set up to attract potential attackers away from a company's network resources.", isCorrect: false },
      ],
    explanation: 'Answer C is correct DNS sinkhole intercepts attempts to visit harmful websites and redirects them so you don\'t end up reaching a malicious website and keeps your computer safe.'
  },
    {
      questionText: "An incident analyst finds several image files on a hard disk. The image files may contain geolocation coordinates. Which of the following best describes the type of information the analyst is trying to extract from the image files?",
      answerOptions: [
        { answerText: 'Log data', isCorrect: false },
        { answerText: 'Metadata', isCorrect: true },
        { answerText: 'Encrypted data', isCorrect: false },
        { answerText: 'Sensitive data', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'Which of the following most likely describes why a security engineer would configure all outbound emails to use S/MIME digital signatures?',
      answerOptions: [
        { answerText: 'To meet compliance standards', isCorrect: false },
        { answerText: 'To increase delivery rates', isCorrect: false },
        { answerText: 'To block phishing attacks', isCorrect: false },
        { answerText: 'To ensure non-repudiation', isCorrect: true },
      ],
    explanation: 'Answer D is correct. S/MIME digital signatures provides a way to ensure that the email has not been altered and that it genuinely comes from the sender (Non-repudiation)'
  },
    {
      questionText: 'During a recent company safety stand-down, the cyber-awareness team gave a presentation on the importance of cyber hygiene. One topic the team covered was best practices for printing centers. Which of the following describes an attack method that relates to printing centers?',
      answerOptions: [
        { answerText: 'Whaling', isCorrect: false },
        { answerText: 'Credential harvesting', isCorrect: false },
        { answerText: 'Prepending', isCorrect: false },
        { answerText: 'Dumpster diving', isCorrect: true },
      ],
    explanation: 'D is correct. In a printing center, sensitive documents that are improperly disposed of could be retrieved from the trash by attackers.'
  },
    {
      questionText: 'Which of the following considerations is the most important regarding cryptography used in an IoT device?',
      answerOptions: [
        { answerText: 'Resource constraints', isCorrect: true },
        { answerText: 'Available bandwidth', isCorrect: false },
        { answerText: 'The use of block ciphers', isCorrect: false },
        { answerText: 'The compatibility of the TLS version', isCorrect: false },
      ],
    explanation: 'A. Resource constraints Resource constraints are critical in IoT devices because these devices often have limited processing power, memory, and battery life. Cryptographic operations can be resource-intensive, so it\'s essential to choose algorithms and protocols that are efficient and suitable for the device\'s capabilities. Failing to consider resource constraints can lead to performance issues or even render the device unable to perform necessary cryptographic operations. The other options are important but generally secondary to ensuring the cryptography can operate within the device\'s resource limitations: B. Available bandwidth: This is relevant for data transmission but is not a primary concern for the cryptography itself. C. The use of block ciphers: Choosing between block ciphers and stream ciphers depends on the specific use case, but resource constraints take precedence. D. The compatibility of the TLS version: This is important for secure communications, but resource constraints must first be addressed to ensure that the device can support any chosen protocol.'
  },
    {
      questionText: 'A coffee shop owner wants to restrict internet access to only paying customers by prompting them for a receipt number. Which of the following is the best method to use given this requirement?',
      answerOptions: [
        { answerText: 'WPA3', isCorrect: false },
        { answerText: 'Captive portal', isCorrect: true },
        { answerText: 'PSK', isCorrect: false },
        { answerText: 'IEEE 802.1X', isCorrect: false },
      ],
    explanation: 'B. Captive portal Explanation: A captive portal is a web page that users are redirected to when they connect to a network. It is commonly used in coffee shops, hotels, and other public places to enforce policies like requiring users to enter a receipt number, agree to terms of use, or log in before granting internet access. Other Options: A. WPA3: A secure Wi-Fi encryption standard, but it does not offer functionality to prompt for receipt numbers or other user-specific authentication. C. PSK (Pre-Shared Key): Uses a shared password for network access but cannot handle individual receipt-based authentication. D. IEEE 802.1X: A port-based network access control protocol typically used in enterprise environments with authentication servers, but it is too complex and not suitable for this requirement.'
  },
    {
      questionText: 'While performing digital forensics, which of the following is considered the most volatile and should have the contents collected first?',
      answerOptions: [
        { answerText: 'Hard drive', isCorrect: false },
        { answerText: 'RAM', isCorrect: true },
        { answerText: 'SSD', isCorrect: false },
        { answerText: 'Temporary files', isCorrect: false },
      ],
    explanation: 'When the computer powers off, anything in the RAM is going to be lost. Therefore, collecting potential evidence out of the RAM is the first thing that should be done out of these options.'
  },
    {
      questionText: "A hosting provider needs to prove that its security controls have been in place over the last six months and have sufficiently protected customer data. Which of the following would provide the best proof that the hosting provider has met the requirements?",
      answerOptions: [
        { answerText: 'NIST CSF', isCorrect: false },
        { answerText: 'SOC 2 Type 2 report', isCorrect: true },
        { answerText: 'CIS Top 20 compliance reports', isCorrect: false },
        { answerText: 'Vulnerability report', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'A city municipality lost its primary data center when a tornado hit the facility. Which of the following should the city staff use immediately after the disaster to handle essential public services?',
      answerOptions: [
        { answerText: 'BCP', isCorrect: true },
        { answerText: 'Communication plan', isCorrect: false },
        { answerText: 'DRP', isCorrect: false },
        { answerText: 'IRP', isCorrect: false },
      ],
    explanation: 'Im going with C, because while a BCP is for helping to ensure that essential business operations continue after a disaster (such as this tornado), it is broader in scope. The DRP offers specific steps and processes to follow to recover critical IT infrastructure and systems, which is the more immediate concern "immediately after the disaster."'
  },
    {
      questionText: 'Which of the following is considered a preventive control?',
      answerOptions: [
        { answerText: 'Configuration auditing', isCorrect: false },
        { answerText: 'Log correlation', isCorrect: false },
        { answerText: 'Incident alerts', isCorrect: false },
        { answerText: 'Segregation of duties', isCorrect: true },
      ],
    explanation: 'Segregation of duties is going to PREVENT users from having the ability to potentially manipulate processes within the business by splitting duties amongst others. Somewhat of a "checks and balances" kind of system.'
  },
    {
      questionText: 'A systems administrator notices that a testing system is down. While investigating, the systems administrator finds that the servers are online and accessible from any device on the server network. The administrator reviews the following information from the monitoring system:Which of the following is the most likely cause of the outage?',
      answerOptions: [
        { answerText: 'Denial of service', isCorrect: true },
        { answerText: 'ARP poisoning', isCorrect: false },
        { answerText: 'Jamming', isCorrect: false },
        { answerText: 'Kerberoasting', isCorrect: false },
      ],
    explanation: 'A Denial of Service. This is clearly indicative of DoS attack where the two Test hosts are being overwhelmed with excessive traffic received causing them to become unresponsive and crash.'
  },
    {
      questionText: 'A security team has been alerted to a flood of incoming emails that have various subject lines and are addressed to multiple email inboxes. Each email contains a URL shortener link that is redirecting to a dead domain. Which of the following is the best step for the security team to take?',
      answerOptions: [
        { answerText: 'Create a blocklist for all subject lines.', isCorrect: false },
        { answerText: 'Send the dead domain to a DNS sinkhole.', isCorrect: false },
        { answerText: 'Quarantine all emails received and notify all employees.', isCorrect: false },
        { answerText: 'Block the URL shortener domain in the web proxy.', isCorrect: true },
      ],
    explanation: 'NOT D. Block the URL shortener domain in the web proxy: Blocking the URL shortener domain in the web proxy is a good idea if you suspect that the malicious URLs lead to a harmful site, but in this case, the links are redirecting to a dead domain. The malicious domain itself is no longer active, so blocking the URL shortener might not address the immediate threat. Additionally, this step doesn\'t prevent other similar attacks with different shorteners or domains in the future.'
  },
    {
      questionText: 'A security administrator is working to secure company data on corporate laptops in case the laptops are stolen. Which of the following solutions should the administrator consider?',
      answerOptions: [
        { answerText: 'Disk encryption', isCorrect: true },
        { answerText: 'Data loss prevention', isCorrect: false },
        { answerText: 'Operating system hardening', isCorrect: false },
        { answerText: 'Boot security', isCorrect: false },
      ],
    explanation: 'It’s funny how in this scenario it’s easy picking but as soon as you apply the same scenario but with remote wipe as one of the options, you’ll have a pretty even split of answers between remote wipe and disk encryption.'
  },
    {
      questionText: 'A company needs to keep the fewest records possible, meet compliance needs, and ensure destruction of records that are no longer needed. Which of the following best describes the policy that meets these requirements?',
      answerOptions: [
        { answerText: 'Security policy', isCorrect: false },
        { answerText: 'Classification policy', isCorrect: false },
        { answerText: 'Retention policy', isCorrect: true },
        { answerText: 'Access control policy', isCorrect: false },
      ],
    explanation: 'C. Retention policy. Reasoning: Security policy: While a security policy is important for protecting sensitive information, it doesn\'t specifically address the retention and destruction of records. Classification policy: A classification policy helps categorize information based on its sensitivity and value, but it doesn\'t provide guidelines for how long records should be retained or when they should be destroyed. Retention policy: A retention policy establishes rules for how long different types of records should be kept and when they can be destroyed. This is exactly what the company needs to meet compliance requirements and minimize the number of records it needs to store. Access control policy: An access control policy governs who can access different types of information. While it\'s important for data protection, it doesn\'t directly address the retention and destruction of records. Therefore, a retention policy is the best option for the company to meet its requirements of keeping the fewest records possible, meeting compliance needs, and ensuring destruction of records that are no longer needed.'
  },
    {
      questionText: 'Which of the following is a common source of unintentional corporate credential leakage in cloud environments?',
      answerOptions: [
        { answerText: 'Code repositories', isCorrect: true },
        { answerText: 'Dark web', isCorrect: false },
        { answerText: 'Threat feeds', isCorrect: false },
        { answerText: 'State actors', isCorrect: false },
        { answerText: 'Vulnerability databases', isCorrect: false },
      ],
    explanation: 'A. Code repositories Code repositories often contain hardcoded credentials, API keys, or other sensitive information that developers may accidentally commit without proper security measures. This can expose these credentials when the code is shared or made public, leading to unintentional leakage of corporate credentials in cloud environments.'
  },
    {
      questionText: 'Which of the following is the best reason an organization should enforce a data classification policy to help protect its most sensitive information?',
      answerOptions: [
        { answerText: 'End users will be required to consider the classification of data that can be used in documents.', isCorrect: false },
        { answerText: 'The policy will result in the creation of access levels for each level of classification.', isCorrect: false },
        { answerText: 'The organization will have the ability to create security requirements based on classification levels.', isCorrect: true },
        { answerText: 'Security analysts will be able to see the classification of data within a document before opening it.', isCorrect: false },
      ],
    explanation: 'The answer C is the best reason because it directly addresses the core benefit of data classification policies: Creating security requirements based on classification levels allows organizations to implement tailored, appropriate security measures for different types of data. This approach ensures that the most sensitive information receives the highest level of protection, while less critical data may have less stringent controls. This targeted approach optimizes security efforts and resource allocation, providing a more effective and efficient way to protect an organization\'s information assets.'
  },
    {
      questionText: 'An analyst is performing a vulnerability scan against the web servers exposed to the internet without a system account. Which of the following is most likely being performed?',
      answerOptions: [
        { answerText: 'Non-credentialed scan', isCorrect: true },
        { answerText: 'Packet capture', isCorrect: false },
        { answerText: 'Privilege escalation', isCorrect: false },
        { answerText: 'System enumeration', isCorrect: false },
        { answerText: 'Passive scan', isCorrect: false },
      ],
    explanation: 'The correct answer is: A. Non-credentialed scan A non-credentialed scan is a vulnerability scan conducted without using login credentials. This type of scan is limited to detecting vulnerabilities that are exposed without needing privileged access. It’s commonly used to assess what an external attacker could potentially see or exploit without having any system account access, which aligns with the scenario described.'
  },
    {
      questionText: 'A security administrator is hardening corporate systems and applying appropriate mitigations by consulting a real-world knowledge base for adversary behavior. Which of the following would be best for the administrator to reference?',
      answerOptions: [
        { answerText: 'MITRE ATT&CK', isCorrect: true },
        { answerText: 'CSIRT', isCorrect: false },
        { answerText: 'CVSS', isCorrect: false },
        { answerText: 'SOAR', isCorrect: false },
      ],
    explanation: 'MITRE ATT&CK is a comprehensive and widely used framework that categorizes and describes the various tactics, techniques and procedures (TTPs) employed by adversaries, it is used for threat intelligence, defensive strategy etc.'
  },
    {
      questionText: 'An architect has a request to increase the speed of data transfer using JSON requests externally. Currently, the organization uses SFTP to transfer data files. Which of the following will most likely meet the requirements?',
      answerOptions: [
        { answerText: 'A website-hosted solution', isCorrect: false },
        { answerText: 'Cloud shared storage', isCorrect: false },
        { answerText: 'A secure email solution', isCorrect: false },
        { answerText: 'Microservices using API', isCorrect: true },
      ],
    explanation: 'D. Microservices Using API By using APIs will allow for increased speed of data transfer compared to file based transfer methods liker SFTP.'
  },
    {
      questionText: 'Which of the following addresses individual rights such as the right to be informed, the right of access, and the right to be forgotten?',
      answerOptions: [
        { answerText: 'GDPR', isCorrect: true },
        { answerText: 'PCI DSS', isCorrect: false },
        { answerText: 'NIST', isCorrect: false },
        { answerText: 'ISO', isCorrect: false },
      ],
    explanation: 'GDPR - General Data Protection Regulation NIST - Network institute of standards and technology, so doesn\'t have that. PCI DSS - Payment Card Industry Data security standards ISO - International standard for Standardisation'
  },
    {
      questionText: 'An administrator is installing an LDAP browser tool in order to view objects in the corporate LDAP directory. Secure connections to the LDAP server are required. When the browser connects to the server, certificate errors are being displayed, and then the connection is terminated. Which of the following is the most likely solution?',
      answerOptions: [
        { answerText: 'The administrator should allow SAN certificates in the browser configuration.', isCorrect: false },
        { answerText: 'The administrator needs to install the server certificate into the local truststore.', isCorrect: true },
        { answerText: 'The administrator should request that the secure LDAP port be opened to the server.', isCorrect: false },
        { answerText: "The administrator needs to increase the TLS version on the organization's RA.", isCorrect: false },
      ],
    explanation: 'B is correct The administrator needs to the server\'s certificate in the local trust store of the machine where LDAP browser tool is being used. This will allow the client to trust the server\'s certificate and establish a secure connection.'
  },
    {
      questionText: 'Which of the following is the most important security concern when using legacy systems to provide production service?',
      answerOptions: [
        { answerText: 'Instability', isCorrect: false },
        { answerText: 'Lack of vendor support', isCorrect: true },
        { answerText: 'Loss of availability', isCorrect: false },
        { answerText: 'Use of insecure protocols', isCorrect: false },
      ],
    explanation: 'The most important security concern with legacy systems is the lack of vendor support. Without vendor support, there are no updates, security patches, or fixes for newly discovered vulnerabilities. This leaves the system exposed to potential attacks that cannot be easily mitigated, increasing the risk of security breaches.'
  },
    {
      questionText: "A security investigation revealed that malicious software was installed on a server using a server administrator's credentials. During the investigation, the server administrator explained that Telnet was regularly used to log in. Which of the following most likely occurred?",
      answerOptions: [
        { answerText: 'A spraying attack was used to determine which credentials to use.', isCorrect: false },
        { answerText: 'A packet capture tool was used to steal the password.', isCorrect: true },
        { answerText: 'A remote-access Trojan was used to install the malware.', isCorrect: false },
        { answerText: 'A dictionary attack was used to log in as the server administrator.', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'A user is requesting Telnet access to manage a remote development web server. Insecure protocols are not allowed for use within any environment. Which of the following should be configured to allow remote access to this server?',
      answerOptions: [
        { answerText: 'HTTPS', isCorrect: false },
        { answerText: 'SNMPv3', isCorrect: false },
        { answerText: 'SSH', isCorrect: true },
        { answerText: 'RDP', isCorrect: false },
        { answerText: 'SMTP', isCorrect: false },
      ],
    explanation: 'SSH is recommended because: It provides strong encryption for all data transmitted It\'s a secure protocol, meeting the requirement of avoiding insecure options It allows secure remote access to servers, which is what you\'re looking for It\'s widely used and supported for development environments It can be used to set up secure tunnels for accessing web servers remotely'
  },
    {
      questionText: 'A security administrator is working to find a cost-effective solution to implement certificates for a large number of domains and subdomains owned by the company. Which of the following types of certificates should the administrator implement?',
      answerOptions: [
        { answerText: 'Wildcard', isCorrect: true },
        { answerText: 'Client certificate', isCorrect: false },
        { answerText: 'Self-signed', isCorrect: false },
        { answerText: 'Code signing', isCorrect: false },
      ],
    explanation: 'A wildcard certificate can be used to secure multiple subdomains under a single domain name. This makes it a cost-effective solution for organizations with a large number of subdomains. By purchasing a single wildcard certificate, the organization can secure all subdomains with a single certificate, reducing the need for multiple individual certificates.'
  },
    {
      questionText: 'An auditor discovered multiple insecure ports on some servers. Other servers were found to have legacy protocols enabled. Which of the following tools did the auditor use to discover these issues?',
      answerOptions: [
        { answerText: 'Nessus', isCorrect: true },
        { answerText: 'curl', isCorrect: false },
        { answerText: 'Wireshark', isCorrect: false },
        { answerText: 'netcat', isCorrect: false },
      ],
    explanation: 'Nessus finds potential vulnerabilities SIEM monitors actual security events and incidents'
  },
    {
      questionText: 'A security analyst received a tip that sensitive proprietary information was leaked to the public. The analyst is reviewing the PCAP and notices traffic between an internal server and an external host that includes the following:...12:47:22.327233 PPPoE [ses 0x8122] IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto IPv6 (41), length 331) 10.5.1.1 > 52.165.16.154: IP6 (hlim E3, next-header TCP (6) paylcad length: 271) 2001:67c:2158:a019::ace.53104 > 2001:0:5ef5:79fd:380c:dddd:a601:24fa.13788: Flags [P.], cksum 0xd7ee (correct), seq 97:348, ack 102, win 16444, length 251...Which of the following was most likely used to exfiltrate the data?',
      answerOptions: [
        { answerText: 'Encapsulation', isCorrect: true },
        { answerText: 'MAC address spoofing', isCorrect: false },
        { answerText: 'Steganography', isCorrect: false },
        { answerText: 'Broken encryption', isCorrect: false },
        { answerText: 'Sniffing via on-path position', isCorrect: false },
      ],
    explanation: 'A. Encapsulation The PCAP shows traffic using IPv6 encapsulated within IPv4 (proto IPv6 (41)), which could be used to hide sensitive data within seemingly normal network traffic. This encapsulation technique can potentially bypass certain security controls and filters, making it an effective method for data exfiltration.'
  },
    {
      questionText: 'A company wants to reduce the time and expense associated with code deployment. Which of the following technologies should the company utilize?',
      answerOptions: [
        { answerText: 'Serverless architecture', isCorrect: true },
        { answerText: 'Thin clients', isCorrect: false },
        { answerText: 'Private cloud', isCorrect: false },
        { answerText: 'Virtual machines', isCorrect: false },
      ],
    explanation: 'AWS Lambda lets you upload code and run functions without managing servers, automatically scaling and charging only for compute time used.'
  },
    {
      questionText: 'A security administrator is performing an audit on a stand-alone UNIX server, and the following message is immediately displayed:(Error 13): /etc/shadow: Permission denied.Which of the following best describes the type of tool that is being used?',
      answerOptions: [
        { answerText: 'Pass-the-hash monitor', isCorrect: false },
        { answerText: 'File integrity monitor', isCorrect: false },
        { answerText: 'Forensic analysis', isCorrect: false },
        { answerText: 'Password cracker', isCorrect: true },
      ],
    explanation: 'Password crackers often attempt to access this file to obtain hashed passwords for cracking.'
  },
    {
      questionText: 'A security administrator needs to create firewall rules for the following protocols: RTP, SIP, H.323. and SRTP. Which of the following does this rule set support?',
      answerOptions: [
        { answerText: 'RTOS', isCorrect: false },
        { answerText: 'VoIP', isCorrect: true },
        { answerText: 'SoC', isCorrect: false },
        { answerText: 'HVAC', isCorrect: false },
      ],
    explanation: 'B. VoIP The protocols RTP (Real-time Transport Protocol), SIP (Session Initiation Protocol), H.323, and SRTP (Secure Real-time Transport Protocol) are commonly used in Voice over IP (VoIP) communications. RTP handles the transport of media streams, SIP manages call setup and control, H.323 is a standard for multimedia communication, and SRTP provides encryption for RTP. Therefore, the firewall rules for these protocols support VoIP.'
  },
    {
      questionText: 'Which of the following best describes a social engineering attack that uses a targeted electronic messaging campaign aimed at a Chief Executive Officer?',
      answerOptions: [
        { answerText: 'Whaling', isCorrect: true },
        { answerText: 'Spear phishing', isCorrect: false },
        { answerText: 'Impersonation', isCorrect: false },
        { answerText: 'Identity fraud', isCorrect: false },
      ],
    explanation: 'Focusing on the Big fish (Whale)'
  },
    {
      questionText: 'During a penetration test, a flaw in the internal PKI was exploited to gain domain administrator rights using specially crafted certificates. Which of the following remediation tasks should be completed as part of the cleanup phase?',
      answerOptions: [
        { answerText: 'Updating the CRL', isCorrect: false },
        { answerText: 'Patching the CA', isCorrect: true },
        { answerText: 'Changing passwords', isCorrect: false },
        { answerText: 'Implementing SOAR', isCorrect: false },
      ],
    explanation: 'B. Patching the CA Here\'s why: Patching the Certificate Authorities: This involves updating the CA software to address the specific vulnerability that was exploited. Since the attack exploited a flaw in the PKI, patching the CA is crucial to fixing the vulnerability and preventing similar attacks in the future. While the other options are also important in a broader security context, they may not directly address the specific issue with the PKI flaw: -Updating the Certificate Revocation Lists (CRLs): This is important for managing revoked certificates but may not address the root cause of the PKI vulnerability. -Changing passwords: This is a good security practice but would not resolve the underlying issue with the PKI vulnerability. -Implementing SOAR (Security Orchestration, Automation, and Response): SOAR can help with automating responses and managing security operations but does not directly address the specific PKI vulnerability. -Therefore, patching the Certificate Authorities is the most effective and direct remediation task for this situatio'
  },
    {
      questionText: 'A company wants to implement MFA. Which of the following enables the additional factor while using a smart card?',
      answerOptions: [
        { answerText: 'PIN', isCorrect: true },
        { answerText: 'Hardware token', isCorrect: false },
        { answerText: 'User ID', isCorrect: false },
        { answerText: 'SMS', isCorrect: false },
      ],
    explanation: 'A. PIN Here’s why: PIN (Personal Identification Number): When using a smart card, the smart card itself serves as one factor (something you have), and the PIN entered to access the smart card provides the second factor (something you know). This combination of something you have (the smart card) and something you know (the PIN) constitutes MFA. The other options are not directly related to the authentication factor provided by the smart card: -Hardware token: This could be another factor for MFA but is not used in conjunction with a smart card; instead, it’s a standalone factor. -User ID: This is usually a username and not a factor in MFA. -SMS: This can be used as an additional factor in some MFA setups but is not directly related to smart cards. It represents a different method of delivering a second factor, such as a one-time passcode sent via text message.'
  },
    {
      questionText: 'A company hired an external consultant to assist with required system upgrades to a critical business application. A systems administrator needs to secure the consultant\'s access without sharing passwords to critical systems. Which of the following solutions should most likely be utilized?',
      answerOptions: [
        { answerText: 'TACACS+', isCorrect: false },
        { answerText: 'SAML', isCorrect: false },
        { answerText: 'An SSO platform', isCorrect: false },
        { answerText: 'Role-based access control', isCorrect: false },
        { answerText: 'PAM software', isCorrect: true },
      ],
    explanation: ''
  },
    {
      questionText: 'A newly implemented wireless network is designed so that visitors can connect to the wireless network for business activities. The legal department is concerned that visitors might connect to the network and perform illicit activities. Which of the following should the security team implement to address this concern?',
      answerOptions: [
        { answerText: 'Configure a RADIUS server to manage device authentication.', isCorrect: false },
        { answerText: 'Use 802.1X on all devices connecting to wireless.', isCorrect: false },
        { answerText: 'Add a guest captive portal requiring visitors to accept terms and conditions.', isCorrect: true },
        { answerText: 'Allow for new devices to be connected via WPS.', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'Which of the following data roles is responsible for identifying risks and appropriate access to data?',
      answerOptions: [
        { answerText: 'Owner', isCorrect: true },
        { answerText: 'Custodian', isCorrect: false },
        { answerText: 'Steward', isCorrect: false },
        { answerText: 'Controller', isCorrect: false },
      ],
    explanation: 'A. Owner The data owner is indeed responsible for identifying risks and determining the appropriate access to data.'
  },
    {
      questionText: 'Which of the following physical controls can be used to both detect and deter? (Choose two.)',
      answerOptions: [
        { answerText: 'Lighting', isCorrect: true },
        { answerText: 'Fencing', isCorrect: false },
        { answerText: 'Signage', isCorrect: false },
        { answerText: 'Sensor', isCorrect: true },
        { answerText: 'Bollard', isCorrect: false },
        { answerText: 'Lock', isCorrect: false },
      ],
    explanation: 'Lighting will illuminate the area, detect people attempting to be under the cover of night, and deter them from committing unwanted acts. Furthermore, a sensor will detect movement in an area, and sensors that are visible can ward off any potential bad actors.'
  },
    {
      questionText: 'A multinational bank hosts several servers in its data center. These servers run a business-critical application used by customers to access their account information. Which of the following should the bank use to ensure accessibility during peak usage times?',
      answerOptions: [
        { answerText: 'Load balancer', isCorrect: true },
        { answerText: 'Cloud backups', isCorrect: false },
        { answerText: 'Geographic dispersal', isCorrect: false },
        { answerText: 'Disk multipathing', isCorrect: false },
      ],
    explanation: 'A. Load balancer A load balancer is the most appropriate solution to ensure accessibility of a business-critical application during peak usage times. It distributes incoming network traffic across multiple servers, optimizing resource utilization, maximizing throughput, minimizing response time, and avoiding overload on any single server. This is particularly crucial for a multinational bank\'s customer-facing application during high-traffic periods.'
  },
    {
      questionText: "The author of a software package is concerned about bad actors repackaging and inserting malware into the software. The software download is hosted on a website, and the author exclusively controls the website's contents. Which of the following techniques would best ensure the software's integrity?",
      answerOptions: [
        { answerText: 'Input validation', isCorrect: false },
        { answerText: 'Code signing', isCorrect: true },
        { answerText: 'Secure cookies', isCorrect: false },
        { answerText: 'Fuzzing', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: "A third-party vendor is moving a particular application to the end-of-life stage at the end of the current year. Which of the following is the most critical risk if the company chooses to continue running the application?",
      answerOptions: [
        { answerText: 'Lack of security updates', isCorrect: true },
        { answerText: 'Lack of new features', isCorrect: false },
        { answerText: 'Lack of support', isCorrect: false },
        { answerText: 'Lack of source code access', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: "A security analyst recently read a report about a flaw in several of the organization's printer models that causes credentials to be sent over the network in cleartext, regardless of the encryption settings. Which of the following would be best to use to validate this finding?",
      answerOptions: [
        { answerText: 'Wireshark', isCorrect: true },
        { answerText: 'netcat', isCorrect: false },
        { answerText: 'Nessus', isCorrect: false },
        { answerText: 'Nmap', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'A development team is launching a new public-facing web product. The Chief Information Security Officer has asked that the product be protected from attackers who use malformed or invalid inputs to destabilize the system. Which of the following practices should the development team implement?',
      answerOptions: [
        { answerText: 'Fuzzing', isCorrect: true },
        { answerText: 'Continuous deployment', isCorrect: false },
        { answerText: 'Static code analysis', isCorrect: false },
        { answerText: 'Manual peer review', isCorrect: false },
      ],
    explanation: 'Fuzzing is "... involves feeding a system with invalid, unexpected, or random inputs, also known as fuzz, to try to crash it or trigger errors.". This is going to be the best answer for this question.'
  },
    {
      questionText: 'During an annual review of the system design, an engineer identified a few issues with the currently released design. Which of the following should be performed next according to best practices?',
      answerOptions: [
        { answerText: 'Risk management process', isCorrect: false },
        { answerText: 'Product design process', isCorrect: false },
        { answerText: 'Design review process', isCorrect: false },
        { answerText: 'Change control process', isCorrect: true },
      ],
    explanation: 'According to best practices, after identifying issues with the currently released design during an annual review, the next step should be: D. Change control process: The change control process ensures that any modifications to the design are systematically evaluated, approved, and documented. This helps in maintaining the integrity of the system and ensures that changes are implemented in a controlled and coordinated manner.'
  },
    {
      questionText: 'Which of the following is best to use when determining the severity of a vulnerability?',
      answerOptions: [
        { answerText: 'CVE', isCorrect: false },
        { answerText: 'OSINT', isCorrect: false },
        { answerText: 'SOAR', isCorrect: false },
        { answerText: 'CVSS', isCorrect: true },
      ],
    explanation: 'D. CVSS (Common Vulnerability Scoring System) Rationale: Provides standardized method for assessing vulnerability severity CVE: Identifies vulnerabilities, doesn\'t score severity OSINT: Open-source intelligence gathering SOAR: Security orchestration and automated response'
  },
    {
      questionText: "An organization experienced a security breach that allowed an attacker to send fraudulent wire transfers from a hardened PC exclusively to the attacker's bank through remote connections. A security analyst is creating a timeline of events and has found a different PC on the network containing malware. Upon reviewing the command history, the analyst finds the following:\nPS>.\\mimikatz.exe \"sekurlsa::pth /user:localadmin /domain:corp-domain.com /ntlm:B4B9B02E1F29A3CF193EAB28C8D617D3F327Which of the following best describes how the attacker gained access to the hardened PC?",
      answerOptions: [
        { answerText: 'The attacker created fileless malware that was hosted by the banking platform.', isCorrect: false },
        { answerText: 'The attacker performed a pass-the-hash attack using a shared support account.', isCorrect: true },
        { answerText: 'The attacker utilized living-off-the-land binaries to evade endpoint detection and response software.', isCorrect: false },
        { answerText: 'The attacker socially engineered the accountant into performing bad transfers.', isCorrect: false },
      ],
    explanation: 'The command history indicates that the attacker used Mimikatz to perform a pass-the-hash (PTH) attack, which involves using a hashed password (NTLM hash) to authenticate without needing to know the plaintext password. This suggests that the attacker exploited the credentials of a local admin account to access the hardened PC.'
  },
    {
      questionText: 'Which of the following is the best resource to consult for information on the most common application exploitation methods?',
      answerOptions: [
        { answerText: 'OWASP', isCorrect: true },
        { answerText: 'STIX', isCorrect: false },
        { answerText: 'OVAL', isCorrect: false },
        { answerText: 'Threat intelligence feed', isCorrect: false },
        { answerText: 'Common Vulnerabilities and Exposures', isCorrect: false },
      ],
    explanation: 'OWASP (Open Web Application Security Project). OWASP provides extensive resources, guidelines, and tools related to web application security, including the OWASP Top 10, which lists the most critical security risks to web applications.'
  },
    {
      questionText: "A security analyst is reviewing the logs on an organization's DNS server and notices the following unusual snippet:Which of the following attack techniques was most likely used?",
      answerOptions: [
        { answerText: "Determining the organization's ISP-assigned address space", isCorrect: false },
        { answerText: "Bypassing the organization's DNS sinkholing", isCorrect: false },
        { answerText: 'Footprinting the internal network', isCorrect: true },
        { answerText: 'Attempting to achieve initial access to the DNS server', isCorrect: false },
        { answerText: 'Exfiltrating data from fshare.int.complia.org', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: "A security analyst at an organization observed several user logins from outside the organization's network. The analyst determined that these logins were not performed by individuals within the organization. Which of the following recommendations would reduce the likelihood of future attacks? (Choose two.)",
      answerOptions: [
        { answerText: 'Disciplinary actions for users', isCorrect: false },
        { answerText: 'Conditional access policies', isCorrect: true },
        { answerText: 'More regular account audits', isCorrect: false },
        { answerText: 'Implementation of additional authentication factors', isCorrect: true },
        { answerText: 'Enforcement of content filtering policies', isCorrect: false },
        { answerText: 'A review of user account permissions', isCorrect: false },
      ],
    explanation: 'B. Conditional access policies: Implementing conditional access policies can restrict access based on certain conditions, such as geographical location, device compliance, or risk level. This would help prevent unauthorized logins from outside the organization’s network.\nD. Implementation of additional authentication factors: Adding multi-factor authentication (MFA) provides an extra layer of security, making it much harder for unauthorized individuals to gain access even if they have the correct credentials.'
  },
    {
      questionText: "A security team is addressing a risk associated with the attack surface of the organization's web application over port 443. Currently, no advanced network security capabilities are in place. Which of the following would be best to set up? (Choose two.)",
      answerOptions: [
        { answerText: 'NIDS', isCorrect: true },
        { answerText: 'Honeypot', isCorrect: false },
        { answerText: 'Certificate revocation list', isCorrect: false },
        { answerText: 'HIPS', isCorrect: false },
        { answerText: 'WAF', isCorrect: true },
        { answerText: 'SIEM', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'A systems administrator would like to create a point-in-time backup of a virtual machine. Which of the following should the administrator use?',
      answerOptions: [
        { answerText: 'Replication', isCorrect: false },
        { answerText: 'Simulation', isCorrect: false },
        { answerText: 'Snapshot', isCorrect: true },
        { answerText: 'Containerization', isCorrect: false },
      ],
    explanation: 'The answer C: To resume at the point you left off'
  },
    {
      questionText: 'A security administrator notices numerous unused, non-compliant desktops are connected to the network. Which of the following actions would the administrator most likely recommend to the management team?',
      answerOptions: [
        { answerText: 'Monitoring', isCorrect: false },
        { answerText: 'Decommissioning', isCorrect: true },
        { answerText: 'Patching', isCorrect: false },
        { answerText: 'Isolating', isCorrect: false },
      ],
    explanation: 'Decommissioning unused and non-compliant desktops will reduce security risks by removing potential points of vulnerability from the network. This action helps to ensure that only compliant and necessary devices are connected, maintaining the integrity and security of the network.'
  },
    {
      questionText: 'Which of the following is a common data removal option for companies that want to wipe sensitive data from hard drives in a repeatable manner but allow the hard drives to be reused?',
      answerOptions: [
        { answerText: 'Sanitization', isCorrect: true },
        { answerText: 'Formatting', isCorrect: false },
        { answerText: 'Degaussing', isCorrect: false },
        { answerText: 'Defragmentation', isCorrect: false },
      ],
    explanation: 'Sanitization is the process of removing sensitive data from a storage device in a manner that ensures the data cannot be recovered while allowing device to be reused. This involves methods like overwriting the data with zeros or other patterns multiple times.'
  },
    {
      questionText: "An organization wants to improve the company's security authentication method for remote employees. Given the following requirements:\n\n• Must work across SaaS and internal network applications\n•  Must be device manufacturer agnostic\n• Must have offline capabilities\n\n Which of the following would be the most appropriate authentication method?",
      answerOptions: [
        { answerText: 'Username and password', isCorrect: false },
        { answerText: 'Biometrics', isCorrect: false },
        { answerText: 'SMS verification', isCorrect: false },
        { answerText: 'Time-based tokens', isCorrect: true },
      ],
    explanation: ''
  },
    {
      questionText: 'A security officer is implementing a security awareness program and has placed security-themed posters around the building and assigned online user training. Which of the following will the security officer most likely implement?',
      answerOptions: [
        { answerText: 'Password policy', isCorrect: false },
        { answerText: 'Access badges', isCorrect: false },
        { answerText: 'Phishing campaign', isCorrect: true },
        { answerText: 'Risk assessment', isCorrect: false },
      ],
    explanation: 'C. Phishing campaign This is simulating phishing attacks to educate employees about recognizing and handling of phishing attempts.'
  },
    {
      questionText: 'A malicious update was distributed to a common software platform and disabled services at many organizations. Which of the following best describes this type of vulnerability?',
      answerOptions: [
        { answerText: 'DDoS attack', isCorrect: false },
        { answerText: 'Rogue employee', isCorrect: false },
        { answerText: 'Insider threat', isCorrect: false },
        { answerText: 'Supply chain', isCorrect: true },
      ],
    explanation: 'This is similar to the recent crowd strike update, hence the answer is Supply Chain'
  },
    {
      questionText: "A company web server is initiating outbound traffic to a low-reputation, public IP on non-standard pat. The web server is used to present an unauthenticated page to clients who upload images the company. An analyst notices a suspicious process running on the server hat was not created by the company development team. Which of the following is the most likely explanation for his security incident?",
      answerOptions: [
        { answerText: 'A web shell has been deployed to the server through the page.', isCorrect: true },
        { answerText: 'A vulnerability has been exploited to deploy a worm to the server.', isCorrect: false },
        { answerText: 'Malicious insiders are using the server to mine cryptocurrency.', isCorrect: false },
        { answerText: 'Attackers have deployed a rootkit Trojan to the server over an exposed RDP port.', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: "An organization requests a third-party full-spectrum analysis of its supply chain. Which of the following would the analysis team use to meet this requirement?",
      answerOptions: [
        { answerText: 'Vulnerability scanner', isCorrect: false },
        { answerText: 'Penetration test', isCorrect: false },
        { answerText: 'SCAP', isCorrect: false },
        { answerText: 'Illumination tool', isCorrect: true },
      ],
    explanation: 'The correct answer is D. Illumination tool. An illumination tool is designed to provide a comprehensive overview and analysis of a supply chain, identifying risks, vulnerabilities, and potential points of failure across the entire spectrum.'
  },
    {
      questionText: 'A systems administrator deployed a monitoring solution that does not require installation on the endpoints that the solution is monitoring. Which of the following is described in this scenario?',
      answerOptions: [
        { answerText: 'Agentless solution', isCorrect: true },
        { answerText: 'Client-based soon', isCorrect: false },
        { answerText: 'Open port', isCorrect: false },
        { answerText: 'File-based solution', isCorrect: false },
      ],
    explanation: 'Agentless monitoring does not require the installation of software on the target device. It uses standard protocols to collect information, making it less intrusive and less resource intensive.'
  },
    {
      questionText: 'A security analyst is reviewing the source code of an application in order to identify misconfigurations and vulnerabilities. Which of the following kinds of analysis best describes this review?',
      answerOptions: [
        { answerText: 'Dynamic', isCorrect: false },
        { answerText: 'Static', isCorrect: true },
        { answerText: 'Gap', isCorrect: false },
        { answerText: 'Impact', isCorrect: false },
      ],
    explanation: 'Static analysis refers to reviewing the source code of an application without executing it, in order to identify misconfigurations, vulnerabilities, and potential security flaws. This is the type of analysis the security analyst is performing by examining the code directly. Dynamic analysis (A) involves analyzing the application while it is running, to detect vulnerabilities that only appear during execution. Gap analysis (C) identifies discrepancies between current security measures and desired standards, but is not focused on source code review. Impact analysis (D) assesses the potential consequences of identified vulnerabilities but is not the process of reviewing source code directly.'
  },
    {
      questionText: 'Which of the following agreement types is used to limit external discussions?',
      answerOptions: [
        { answerText: 'BPA', isCorrect: false },
        { answerText: 'NDA', isCorrect: true },
        { answerText: 'SLA', isCorrect: false },
        { answerText: 'MSA', isCorrect: false },
      ],
    explanation: 'A. BPA: Business Process Automation B. NDA: Non-Disclosure Agreement C. SLA: Service Level Agreement D. MSA: Master Service Agreement'
  },
    {
      questionText: 'A security analyst is evaluating a SaaS application that the human resources department would like to implement. The analyst requests a SOC 2 report from the SaaS vendor. Which of the following processes is the analyst most likely conducting?',
      answerOptions: [
        { answerText: 'Internal audit', isCorrect: false },
        { answerText: 'Penetration testing', isCorrect: false },
        { answerText: 'Attestation', isCorrect: false },
        { answerText: 'Due diligence', isCorrect: true },
      ],
    explanation: 'D. Due diligence In this context, due diligence refers to the process of evaluating the security, compliance, and risk associated with a third-party vendor or service, such as a SaaS application. Requesting a SOC 2 report is a common part of the due diligence process to assess the vendor\'s controls related to security, availability, processing integrity, confidentiality, and privacy. Internal audit (A) refers to an organization\'s internal review of its own processes, not an external vendor. Penetration testing (B) involves actively testing for vulnerabilities by simulating attacks, which is not applicable here. Attestation (C) refers to a third-party audit or certification, such as the SOC 2 report itself, but the analyst is conducting due diligence by requesting the report.'
  },
    {
      questionText: 'Which of the following is used to conceal credit card information in a database log file?',
      answerOptions: [
        { answerText: 'Tokenization', isCorrect: false },
        { answerText: 'Masking', isCorrect: true },
        { answerText: 'Hashing', isCorrect: false },
        { answerText: 'Obfuscation', isCorrect: false },
      ],
    explanation: 'B. Masking Masking is used to conceal sensitive information, such as credit card numbers, by replacing or hiding parts of the data. In the context of database log files, masking ensures that sensitive information is not exposed while maintaining the usability of the data for other purposes. Tokenization (A) replaces sensitive data with a token that can only be mapped back to the original data using a secure system, but it is not typically used for log file entries. Hashing (C) converts data into a fixed-length hash, but it\'s a one-way function, making it unsuitable if the original data needs to be retrieved. Obfuscation (D) refers to making data less understandable but is less structured and secure than masking for specific data like credit card numbers.'
  },
    {
      questionText: "An organization recently started hosting a new service that customers access through a web portal. A security engineer needs to add to the existing security devices a new solution to protect this new service. Which of the following is the engineer most likely to deploy?",
      answerOptions: [
        { answerText: 'Layer 4 firewall', isCorrect: false },
        { answerText: 'NGFW', isCorrect: false },
        { answerText: 'WAF', isCorrect: true },
        { answerText: 'UTM', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: "Which of the following topics would most likely be included within an organization's SDLC?",
      answerOptions: [
        { answerText: 'Service-level agreements', isCorrect: false },
        { answerText: 'Information security policy', isCorrect: false },
        { answerText: 'Penetration testing methodology', isCorrect: false },
        { answerText: 'Branch protection requirements', isCorrect: true },
      ],
    explanation: ''
  },
    {
      questionText: 'Which of the following control types is AUP an example of?',
      answerOptions: [
        { answerText: 'Physical', isCorrect: false },
        { answerText: 'Managerial', isCorrect: true },
        { answerText: 'Technical', isCorrect: false },
        { answerText: 'Operational', isCorrect: false },
      ],
    explanation: 'Direct from Dion Training\'s Udemy course: Managerial Controls - Aka administrative controls. Involve the strategic planning and governance side of security. Ensures that the org’s security strategies align with its business goals and its risk tolerance. Risk assessments Security policies Training programs Incident response strategies Operational Controls - Procedures and measures designed to protect data on a day-to-day basis and are mainly governed by internal processes and human actions. Backup procedures Account reviews User awareness training programs AUP = Acceptable Use Policy. Security policies = Managerial Controls.'
  },
    {
      questionText: 'An organization is adopting cloud services at a rapid pace and now has multiple SaaS applications in use. Each application has a separate log-in, so the security team wants to reduce the number of credentials each employee must maintain. Which of the following is the first step the security team should take?',
      answerOptions: [
        { answerText: 'Enable SAML.', isCorrect: false },
        { answerText: 'Create OAuth tokens.', isCorrect: false },
        { answerText: 'Use password vaulting.', isCorrect: false },
        { answerText: 'Select an IdP.', isCorrect: true },
      ],
    explanation: 'Chat GPT: The correct answer is D. Select an IdP (Identity Provider). The first step in reducing the number of credentials employees must maintain is to select an Identity Provider (IdP). An IdP centralizes authentication and allows users to log in once and gain access to multiple applications, usually through a single sign-on (SSO) mechanism. Once an IdP is in place, other technologies like SAML (Security Assertion Markup Language) or OAuth can be configured to manage authentication with the SaaS applications. A. Enable SAML is a protocol used for authentication, but it requires an IdP to manage authentication. B. Create OAuth tokens is a way to grant limited access to resources but also requires an IdP or similar system to manage identities. C. Use password vaulting is a temporary solution that stores passwords, but it doesn\'t reduce the need for multiple log-ins, nor does it provide the benefits of centralized identity management.'
  },
    {
      questionText: "A company's online shopping website became unusable shortly after midnight on January 30, 2023. When a security analyst reviewed the database server, the analyst noticed the following code used for backing up data:Which of the following should the analyst do next?",
      answerOptions: [
        { answerText: 'Check for recently terminated DBAs.', isCorrect: true },
        { answerText: 'Review WAF logs for evidence of command injection.', isCorrect: false },
        { answerText: 'Scan the database server for malware.', isCorrect: false },
        { answerText: 'Search the web server for ransomware notes.', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'Which of the following would be the best way to test resiliency in the event of a primary power failure?',
      answerOptions: [
        { answerText: 'Parallel processing', isCorrect: false },
        { answerText: 'Tabletop exercise', isCorrect: false },
        { answerText: 'Simulation testing', isCorrect: false },
        { answerText: 'Production failover', isCorrect: true },
      ],
    explanation: 'The correct answer is: D. Production failover Explanation: Production failover tests the resiliency of systems in the event of a primary power failure by switching operations from the primary system to a backup or secondary system in a live environment. It ensures that the failover process works as intended and that systems remain operational during an actual outage. Other Options: A. Parallel processing: Refers to splitting tasks across multiple systems for efficiency and does not test resiliency in case of a power failure. B. Tabletop exercise: A discussion-based exercise to simulate scenarios but does not involve actual testing of systems. C. Simulation testing: Tests a simulated environment but may not reflect real-world conditions as accurately as a production failover. Production failover is the best way to test resiliency because it verifies that systems can handle a power failure in a real, operational environment.'
  },
    {
      questionText: 'Which of the following would be the most appropriate way to protect data in transit?',
      answerOptions: [
        { answerText: 'SHA-256', isCorrect: false },
        { answerText: 'SSL3.0', isCorrect: false },
        { answerText: 'TLS 1.3', isCorrect: true },
        { answerText: 'AES-256', isCorrect: false },
      ],
    explanation: 'Chat GPT:The correct answer is C. TLS 1.3. TLS (Transport Layer Security) 1.3 is the most appropriate protocol for protecting data in transit, as it provides encryption, integrity, and secure authentication between two communicating parties. It is an updated, secure version of SSL/TLS and is widely recommended for secure communication over networks. A. SHA-256 is a hashing algorithm, primarily used for ensuring data integrity, not for encrypting data in transit. B. SSL 3.0 is an outdated and vulnerable protocol that should no longer be used for securing data. D. AES-256 is an encryption algorithm, but it is typically used for data at rest or as part of protocols like TLS for data in transit; by itself, it is not a protocol for securing data in transit.'
  },
    {
      questionText: 'Which of the following is a common, passive reconnaissance technique employed by penetration testers in the early phases of an engagement?',
      answerOptions: [
        { answerText: 'Open-source intelligence', isCorrect: true },
        { answerText: 'Port scanning', isCorrect: false },
        { answerText: 'Pivoting', isCorrect: false },
        { answerText: 'Exploit validation', isCorrect: false },
      ],
    explanation: 'correct answer if A. OSINT'
  },
    {
      questionText: 'Which of the following threat actors is the most likely to seek financial gain through the use of ransomware attacks?',
      answerOptions: [
        { answerText: 'Organized crime', isCorrect: true },
        { answerText: 'Insider threat', isCorrect: false },
        { answerText: 'Nation-state', isCorrect: false },
        { answerText: 'Hacktivists', isCorrect: false },
      ],
    explanation: 'ORGANIZED CRIME is the answer.'
  },
    {
      questionText: 'Which of the following would a systems administrator follow when upgrading the firmware of an organization’s router?',
      answerOptions: [
        { answerText: 'Software development life cycle', isCorrect: false },
        { answerText: 'Risk tolerance', isCorrect: false },
        { answerText: 'Certificate signing request', isCorrect: false },
        { answerText: 'Maintenance window', isCorrect: true },
      ],
    explanation: 'The correct answer is D. Maintenance window. Explanation: When upgrading the firmware of an organization\'s router, a systems administrator would typically follow a maintenance window.'
  },
    {
      questionText: 'The security team has been asked to only enable host A (10.2.2.7) and host B (10.3.9.9) to the new isolated network segment (10.9.8.14) that provides access to legacy devices. Access from all other hosts should be blocked. Which of the following entries would need to be added on the firewall?',
      answerOptions: [
        { answerText: 'Permit 10.2.2.0/24 to 10.9.8.14/27\nPermit 10.3.9.0/24 to 10.9.8.14/27\nDeny 0.0.0.0/0 to 10.9.8.14/27', isCorrect: false}, 
        { answerText: 'Deny 0.0.0.0/0 to 10.9.8.14/27\nPermit 10.2.2.0/24 to 10.9.8.14/27\nPermit 10.3.9.0/24 to 10.9.8.14/27', isCorrect: false},
        { answerText: 'Permit 10.2.2.7/32 to 10.9.8.14/27\nPermit 10.3.9.9/32 to 10.9.8.14/27\nDeny 0.0.0.0/0 to 10.9.8.14/27', isCorrect: true },
        { answerText: 'Permit 10.2.2.7/32 to 10.9.8.14/27\nPermit 10.3.9.0/24 to 10.9.8.14/27\nDeny 10.9.8.14/27 to 0.0.0.0/0', isCorrect: false},
      ],
    explanation: ''
  },
    {
      questionText: 'A systems administrator needs to ensure the secure communication of sensitive data within the organization’s private cloud. Which of the following is the best choice for the administrator to implement?',
      answerOptions: [
        { answerText: 'IPSec', isCorrect: true },
        { answerText: 'SHA-1', isCorrect: false },
        { answerText: 'RSA', isCorrect: false },
        { answerText: 'TGT', isCorrect: false },
      ],
    explanation: 'A. IPSec. IPSec (Internet Protocol Security) is a suite of protocols designed specifically to secure IP communications by authenticating and encrypting each IP packet in a communication session. It’s widely used to protect data in transit—making it ideal for securing sensitive communications within a private cloud environment. Let’s break down the others: - B. SHA-1 is a hashing algorithm, not an encryption or communication protocol—and it\'s considered weak and deprecated. - C. RSA is an encryption algorithm used for secure key exchange, but it’s not a complete communication protocol on its own. - D. TGT (Ticket Granting Ticket) is part of Kerberos authentication, which helps with identity verification but doesn’t secure data transmission directly'
  },
    {
      questionText: 'Which of the following should an internal auditor check for first when conducting an audit of the organization’s risk management program?',
      answerOptions: [
        { answerText: 'Policies and procedures', isCorrect: true },
        { answerText: 'Asset management', isCorrect: false },
        { answerText: 'Vulnerability assessment', isCorrect: false },
        { answerText: 'Business impact analysis', isCorrect: false },
      ],
    explanation: 'The correct answer is: A. Policies and procedures Explanation: When conducting an audit of an organization\'s risk management program, the internal auditor should first review the policies and procedures. These documents form the foundation of the risk management program by outlining the organization’s approach, goals, roles, responsibilities, and processes for managing risks.'
  },
    {
      questionText: 'Which of the following activities are associated with vulnerability management? (Choose two.)',
      answerOptions: [
        { answerText: 'Reporting', isCorrect: true },
        { answerText: 'Prioritization', isCorrect: true },
        { answerText: 'Exploiting', isCorrect: false },
        { answerText: 'Correlation', isCorrect: false },
        { answerText: 'Containment', isCorrect: false },
        { answerText: 'Tabletop exercise', isCorrect: false },
      ],
    explanation: 'A. Reporting: Regularly documenting and reporting on vulnerabilities, including their status, potential risks, and the actions taken to remediate them, is a core part of the vulnerability management process. This helps to track progress and ensure that vulnerabilities are addressed in a timely manner. B. Prioritization: Given that not all vulnerabilities are equally critical, prioritizing them based on factors like the severity of the vulnerability, the risk to the organization, and the potential impact is essential. This helps to allocate resources efficiently and address the most pressing vulnerabilities first NOT E. Containment. Containment is an activity typically associated with incident response or a breach management process. While related to managing security risks, containment is not specifically a part of vulnerability management, which focuses more on identifying, assessing, and mitigating vulnerabilities.'
  },
    {
      questionText: 'An administrator wants to perform a risk assessment without using proprietary company information. Which of the following methods should the administrator use to gather information?',
      answerOptions: [
        { answerText: 'Network scanning', isCorrect: false },
        { answerText: 'Penetration testing', isCorrect: false },
        { answerText: 'Open-source intelligence', isCorrect: true },
        { answerText: 'Configuration auditing', isCorrect: false },
      ],
    explanation: 'The correct answer is: C. Open-source intelligence Explanation: Open-source intelligence (OSINT) involves gathering publicly available information from sources such as websites, social media, forums, and other publicly accessible data to perform a risk assessment. This method allows an administrator to gather useful insights without accessing or relying on proprietary company information.'
  },
    {
      questionText: 'A systems administrator is concerned about vulnerabilities within cloud computing instances. Which of the following is most important for the administrator to consider when architecting a cloud computing environment?',
      answerOptions: [
        { answerText: 'SQL injection', isCorrect: false },
        { answerText: 'TOC/TOU', isCorrect: false },
        { answerText: 'VM escape', isCorrect: true },
        { answerText: 'Tokenization', isCorrect: false },
        { answerText: 'Password spraying', isCorrect: false },
      ],
    explanation: 'C. VM escape. VM escape is a critical vulnerability in cloud environments where multiple virtual machines (VMs) share the same physical host. If an attacker successfully exploits a VM escape flaw, they can break out of the isolated VM and gain control over the hypervisor or other VMs—essentially compromising the entire host system. This undermines the core security model of virtualization, which is foundational to cloud computing. Let’s briefly look at the others: - A. SQL injection is a serious application-layer threat, but it’s not unique to cloud architecture. - B. TOC/TOU (Time-of-check to time-of-use) is a race condition issue, more relevant to OS-level programming. - D. Tokenization is a mitigation technique, not a vulnerability. - E. Password spraying is a brute-force attack vector, but it’s more about identity protection than cloud architecture design.'
  },
    {
      questionText: 'A database administrator is updating the company’s SQL database, which stores credit card information for pending purchases. Which of the following is the best method to secure the data against a potential breach?',
      answerOptions: [
        { answerText: 'Hashing', isCorrect: false },
        { answerText: 'Obfuscation', isCorrect: false },
        { answerText: 'Tokenization', isCorrect: true },
        { answerText: 'Masking', isCorrect: false },
      ],
    explanation: 'In the case of storing credit card information, tokenization is ideal because it: Minimizes risk: Even if attackers gain access to the database, they cannot use the tokens to access the original credit card information. Complies with PCI DSS: Tokenization is widely recommended for compliance with Payment Card Industry Data Security Standards (PCI DSS), which govern the storage of credit card data.'
  },
    {
      questionText: 'Which of the following is a benefit of vendor diversity?',
      answerOptions: [
        { answerText: 'Patch availability', isCorrect: false },
        { answerText: 'Zero-day resiliency', isCorrect: true },
        { answerText: 'Secure configuration guide applicability', isCorrect: false },
        { answerText: 'Load balancing', isCorrect: false },
      ],
    explanation: 'B. Zero-day resiliency: By diversifying vendors, organizations can minimize the impact of zero-day vulnerabilities because not all systems or solutions would rely on the same vendor’s potentially vulnerable software. This reduces the likelihood that a single exploit could compromise the entire infrastructure.'
  },
    {
      questionText: 'An employee used a company’s billing system to issue fraudulent checks. The administrator is looking for evidence of other occurrences of this activity. Which of the following should the administrator examine?',
      answerOptions: [
        { answerText: 'Application logs', isCorrect: true },
        { answerText: 'Vulnerability scanner logs', isCorrect: false },
        { answerText: 'IDS/IPS logs', isCorrect: false },
        { answerText: 'Firewall logs', isCorrect: false },
      ],
    explanation: 'A. Application logs Explanation: Application logs contain detailed information about the operations of specific applications, such as the billing system in question. These logs can provide records of user activities, system events, transactions, and other relevant information related to the fraudulent issuance of checks.'
  },
    {
      questionText: 'An organization is looking to optimize its environment and reduce the number of patches necessary for operating systems. Which of the following will best help to achieve this objective?',
      answerOptions: [
        { answerText: 'Microservices', isCorrect: false },
        { answerText: 'Virtualization', isCorrect: false },
        { answerText: 'Real-time operating system', isCorrect: false },
        { answerText: 'Containers', isCorrect: true },
      ],
    explanation: 'Few popular containers: Docker containers, Windows Containers, Windows Server Containers, Hyper-V Containers, Azure Container Instances (ACI), Microsoft\'s serverless container offering Azure Kubernetes Service (AKS) Managed Kubernetes service for container orchestration Azure Container Registry (ACR) For storing and managing container images'
  },
    {
      questionText: 'Which of the following tasks is typically included in the BIA process?',
      answerOptions: [
        { answerText: 'Estimating the recovery time of systems', isCorrect: true },
        { answerText: 'Identifying the communication strategy', isCorrect: false },
        { answerText: 'Evaluating the risk management plan', isCorrect: false },
        { answerText: 'Establishing the backup and recovery procedures', isCorrect: false },
        { answerText: 'Developing the incident response plan', isCorrect: false },
      ],
    explanation: 'Business Impact Analysis (BIA) = Recovery Time Objectives (RTO) + Recovery Point Objectives (RPO)'
  },
    {
      questionText: 'Which of the following is a risk of conducting a vulnerability assessment?',
      answerOptions: [
        { answerText: 'A disruption of business operations', isCorrect: true },
        { answerText: 'Unauthorized access to the system', isCorrect: false },
        { answerText: 'Reports of false positives', isCorrect: false },
        { answerText: 'Finding security gaps in the system', isCorrect: false },
      ],
    explanation: 'Its A because it asks specically for the RISK in a vunerability assessment. A False Positive is just a result of a vulnerability assessment.'
  },
    {
      questionText: 'Which of the following techniques would attract the attention of a malicious attacker in an insider threat scenario?',
      answerOptions: [
        { answerText: 'Creating a false text file in /docs/salaries', isCorrect: true },
        { answerText: 'Setting weak passwords in /etc/shadow', isCorrect: false },
        { answerText: 'Scheduling vulnerable jobs in /etc/crontab', isCorrect: false },
        { answerText: 'Adding a fake account to /etc/passwd', isCorrect: false },
      ],
    explanation: 'A. Creating a false text file in /docs/salaries Explanation: This technique is an example of setting up a honeypot or decoy. A false text file labeled something enticing like "salaries" could attract the attention of an insider threat. If the malicious insider attempts to access it, their behavior can be monitored or flagged. This method does not compromise system security but instead acts as bait to detect malicious activity. Other Options: B. Setting weak passwords in /etc/shadow: Weak passwords would compromise system security and invite external attackers rather than serving as a monitoring tactic. C. Scheduling vulnerable jobs in /etc/crontab: This could lead to system exploitation and does not serve as a targeted method for insider threat detection.'
  },
    {
      questionText: 'An organization maintains intellectual property that it wants to protect. Which of the following concepts would be most beneficial to add to the company’s security awareness training program?',
      answerOptions: [
        { answerText: 'Insider threat detection', isCorrect: true },
        { answerText: 'Simulated threats', isCorrect: false },
        { answerText: 'Phishing awareness', isCorrect: false },
        { answerText: 'Business continuity planning', isCorrect: false },
      ],
    explanation: 'Insider threats can include activities like stealing proprietary information, leaking sensitive data, or mishandling IP. Ensuring that employees are aware of the signs of potential insider threats and how to report suspicious activity is critical to protecting intellectual property. Effective insider threat detection involves monitoring for unusual behavior or actions that could indicate misuse of access to intellectual property, such as unauthorized copying, sharing, or downloading of sensitive data.'
  },
    {
      questionText: 'An organization plans to expand its operations internationally and needs to keep data at the new location secure. The organization wants to use the most secure architecture model possible. Which of the following models offers the highest level of security?',
      answerOptions: [
        { answerText: 'Cloud-based', isCorrect: false },
        { answerText: 'Peer-to-peer', isCorrect: false },
        { answerText: 'On-premises', isCorrect: true },
        { answerText: 'Hybrid', isCorrect: false },
      ],
    explanation: 'how much money is involved. I mean C if unlimited money and top tier employees. id use cloud for ease of use for international functionality and advanced security'
  },
    {
      questionText: 'Which of the following is the most relevant reason a DPO would develop a data inventory?',
      answerOptions: [
        { answerText: 'To manage data storage requirements better', isCorrect: false },
        { answerText: 'To determine the impact in the event of a breach', isCorrect: true },
        { answerText: 'To extend the length of time data can be retained', isCorrect: false },
        { answerText: 'To automate the reduction of duplicated data', isCorrect: false },
      ],
    explanation: 'B is the correct answer because the Data Protection Officer (DPO) is responsible for ensuring that an organization complies with data protection regulations like GDPR. Developing a data inventory (also known as a data map) provides a clear understanding of: What data the organization holds Where it is stored How it is processed Who has access to it'
  },
    {
      questionText: 'Which of the following cryptographic solutions protects data at rest?',
      answerOptions: [
        { answerText: 'Digital signatures', isCorrect: false },
        { answerText: 'Full disk encryption', isCorrect: true },
        { answerText: 'Private key', isCorrect: false },
        { answerText: 'Steganography', isCorrect: false },
      ],
    explanation: 'Whole-disk encryption or Full Disk Encryption is a cryptographic solution that protects data at rest. It ensures that the data on a storage device is encrypted, making it unreadable to unauthorized users even if the device is lost or stolen.'
  },
    {
      questionText: 'Which of the following should an organization use to protect its environment from external attacks conducted by an unauthorized hacker?',
      answerOptions: [
        { answerText: 'ACL', isCorrect: false },
        { answerText: 'IDS', isCorrect: false },
        { answerText: 'HIDS', isCorrect: false },
        { answerText: 'NIPS', isCorrect: true },
      ],
    explanation: 'D. NIPS (Network-based Intrusion Prevention System) Explanation: NIPS (Network-based Intrusion Prevention System): A NIPS is specifically designed to monitor network traffic for malicious activity or violations of security policies. It works at the network level, analyzing incoming and outgoing traffic for known attack patterns and behaviors.'
  },
    {
      questionText: 'Which of the following would enable a data center to remain operational through a multiday power outage?',
      answerOptions: [
        { answerText: 'Generator', isCorrect: true },
        { answerText: 'Uninterruptible power supply', isCorrect: false },
        { answerText: 'Replication', isCorrect: false },
        { answerText: 'Parallel processing', isCorrect: false },
      ],
    explanation: 'A generator is the most appropriate solution to keep a data center operational through a multiday power outage. Generators provide backup power over a long period, allowing the data center to continue running when the primary power source is unavailable. Generators typically run on fuel (diesel, natural gas, etc.) and can sustain power for extended durations, depending on the fuel supply. This is critical for ensuring that the data center does not experience downtime during prolonged outages'
  },
    {
      questionText: 'A company installed cameras and added signs to alert visitors that they are being recorded. Which of the following controls did the company implement? (Choose two.)',
      answerOptions: [
        { answerText: 'Directive', isCorrect: false },
        { answerText: 'Deterrent', isCorrect: true },
        { answerText: 'Preventive', isCorrect: false },
        { answerText: 'Detective', isCorrect: true },
        { answerText: 'Corrective', isCorrect: false },
        { answerText: 'Technical', isCorrect: false },
      ],
    explanation: 'I chose B - Deterrent and C - Preventive simply because the question asks about the signs themselves.'
  },
    {
      questionText: 'Which of the following is the best way to securely store an encryption key for a data set in a manner that allows multiple entities to access the key when needed?',
      answerOptions: [
        { answerText: 'Public key infrastructure', isCorrect: false },
        { answerText: 'Open public ledger', isCorrect: false },
        { answerText: 'Public key encryption', isCorrect: false },
        { answerText: 'Key escrow', isCorrect: true },
      ],
    explanation: 'Key escrow refers to a system where encryption keys are stored in a secure, third-party repository, allowing authorized entities (such as specific individuals or organizations) to access the key when necessary.'
  },
    {
      questionText: 'For which of the following reasons would a systems administrator leverage a 3DES hash from an installer file that is posted on a vendor’s website?',
      answerOptions: [
        { answerText: 'To test the integrity of the file', isCorrect: true },
        { answerText: 'To validate the authenticity of the file', isCorrect: false },
        { answerText: 'To activate the license for the file', isCorrect: false },
        { answerText: 'To calculate the checksum of the file', isCorrect: false },
      ],
    explanation: '3DES (Triple DES) stands for Triple Data Encryption Standard It\'s an encryption algorithm that: Takes the original DES (Data Encryption Standard) algorithm Applies it three times to each data block Uses three different keys in sequence: Encrypt with Key 1 Decrypt with Key 2 Encrypt with Key 3 Key characteristics: Block size: 64 bits Key size: 168 bits (three 56-bit keys) More secure than single DES Slower than newer algorithms like AES Still used in some legacy systems While 3DES is more secure than single DES, it\'s generally considered obsolete for new applications, with AES (Advanced Encryption Standard) being the preferred modern encryption standard. 3DES (Triple DES) is actually an encryption algorithm, not a hashing algorithm.'
  },
    {
      questionText: 'A company is redesigning its infrastructure and wants to reduce the number of physical servers in use. Which of the following architectures is best suited for this goal?',
      answerOptions: [
        { answerText: 'Isolation', isCorrect: false },
        { answerText: 'Segmentation', isCorrect: false },
        { answerText: 'Virtualization', isCorrect: true },
        { answerText: 'Redundancy', isCorrect: false },
      ],
    explanation: 'Virtualization allows multiple virtual machines (VMs) to run on a single physical server, reducing the number of physical servers needed. This approach maximizes resource utilization, simplifies management, and lowers costs while providing flexibility to scale and isolate workloads as needed'
  },
    {
      questionText: 'Which of the following security concepts is being followed when implementing a product that offers protection against DDoS attacks?',
      answerOptions: [
        { answerText: 'Availability', isCorrect: true },
        { answerText: 'Non-repudiation', isCorrect: false },
        { answerText: 'Integrity', isCorrect: false },
        { answerText: 'Confidentiality', isCorrect: false },
      ],
    explanation: 'A. Availability Explanation: Availability refers to ensuring that systems, services, and data are accessible and operational when needed, even under potential threats like Distributed Denial of Service (DDoS) attacks. A DDoS attack aims to overwhelm a target system, causing it to become unavailable to legitimate users.'
  },
    {
      questionText: 'A security manager created new documentation to use in response to various types of security incidents. Which of the following is the next step the manager should take?',
      answerOptions: [
        { answerText: 'Set the maximum data retention policy.', isCorrect: false },
        { answerText: 'Securely store the documents on an air-gapped network.', isCorrect: false },
        { answerText: 'Review the documents’ data classification policy.', isCorrect: false },
        { answerText: 'Conduct a tabletop exercise with the team.', isCorrect: true },
      ],
    explanation: 'After creating new documentation for responding to security incidents, the next logical step is to ensure that the documentation is practical, effective, and understood by the team. A tabletop exercise is a simulated discussion-based activity where team members review and practice the steps outlined in the documentation in response to hypothetical security incidents. This helps: Identify gaps or inconsistencies in the documentation. Ensure team members understand their roles and responsibilities during an incident. Test the incident response plan in a controlled environment without disrupting operations.'
  },
    {
      questionText: 'After failing an audit twice, an organization has been ordered by a government regulatory agency to pay fines. Which of the following causes this action?',
      answerOptions: [
        { answerText: 'Non-compliance', isCorrect: true },
        { answerText: 'Contract violations', isCorrect: false },
        { answerText: 'Government sanctions', isCorrect: false },
        { answerText: 'Rules of engagement', isCorrect: false },
      ],
    explanation: 'A. Non-compliance Explanation: Failing an audit twice and being ordered to pay fines by a government regulatory agency indicates that the organization has not met required legal, regulatory, or industry compliance standards. This is known as non-compliance. Regulatory agencies (e.g., GDPR, HIPAA, PCI DSS, SOX) enforce security, privacy, and financial controls. Repeated audit failures signal continued non-compliance, leading to penalties, fines, or legal action. Examples: GDPR fines for mishandling personal data. HIPAA penalties for healthcare data breaches. PCI DSS fines for failing to secure payment data.'
  },
    {
      questionText: 'A company is developing a critical system for the government and storing project information on a fileshare. Which of the following describes how this data will most likely be classified? (Choose two.)',
      answerOptions: [
        { answerText: 'Private', isCorrect: false },
        { answerText: 'Confidential', isCorrect: true },
        { answerText: 'Public', isCorrect: false },
        { answerText: 'Operational', isCorrect: false },
        { answerText: 'Urgent', isCorrect: false },
        { answerText: 'Restricted', isCorrect: true },
      ],
    explanation: 'The correct answers are: B. Confidential F. Restricted Explanation: When developing a critical system for the government, the data involved is sensitive and must be protected. Here\'s why these classifications apply: Confidential: This classification is often used for data that is sensitive and should only be accessible to authorized personnel to protect the integrity and confidentiality of the project. Restricted: This is a stricter classification indicating that access is limited to those with a need-to-know basis, often because the data is critical to national security or contains sensitive government information. Other Options: A. Private: While sensitive, "private" is typically associated with personal data, not government project data. C. Public: Public classification is for data that can be shared openly, which does not apply to critical government projects.'
  },
    {
      questionText: 'Which of the following activities is included in the post-incident review phase?',
      answerOptions: [
        { answerText: 'Determining the root cause of the incident', isCorrect: true },
        { answerText: 'Developing steps to mitigate the risks of the incident', isCorrect: false },
        { answerText: 'Validating the accuracy of the evidence collected during the investigation', isCorrect: false },
        { answerText: 'Reestablishing the compromised system’s configuration and settings', isCorrect: false },
      ],
    explanation: 'From Study Guide: The lessons learned process should invoke root cause analysis or the effort to determine how the incident was able to occur.'
  },
    {
      questionText: 'Which of the following attacks exploits a potential vulnerability as a result of using weak cryptographic algorithms?',
      answerOptions: [
        { answerText: 'Password cracking', isCorrect: true },
        { answerText: 'On-path', isCorrect: false },
        { answerText: 'Digital signing', isCorrect: false },
        { answerText: 'Side-channel', isCorrect: false },
      ],
    explanation: 'A. Password cracking'
  },
    {
      questionText: 'Which of the following is a preventive physical security control?',
      answerOptions: [
        { answerText: 'Video surveillance system', isCorrect: false },
        { answerText: 'Bollards', isCorrect: true },
        { answerText: 'Alarm system', isCorrect: false },
        { answerText: 'Motion sensors', isCorrect: false },
      ],
    explanation: 'Bollards: physical barrier, prevent vehicles access'
  },
    {
      questionText: 'Which of the following is most likely to be used as a just-in-time reference document within a security operations center?',
      answerOptions: [
        { answerText: 'Change management policy', isCorrect: false },
        { answerText: 'Risk profile', isCorrect: false },
        { answerText: 'Playbook', isCorrect: true },
        { answerText: 'SIEM profile', isCorrect: false },
      ],
    explanation: 'C. A playbook is a practical, action-oriented document that provides step-by-step instructions for responding to specific security incidents or scenarios. Security operations center (SOC) analysts commonly use playbooks as just-in-time reference materials to ensure consistent and efficient responses to security events, such as handling phishing emails or mitigating DDoS attacks.'
  },
    {
      questionText: 'A security engineer configured a remote access VPN. The remote access VPN allows end users to connect to the network by using an agent that is installed on the endpoint, which establishes an encrypted tunnel. Which of the following protocols did the engineer most likely implement?',
      answerOptions: [
        { answerText: 'GRE', isCorrect: false },
        { answerText: 'IPSec', isCorrect: true },
        { answerText: 'SD-WAN', isCorrect: false },
        { answerText: 'EAP', isCorrect: false },
      ],
    explanation: 'IPsec the protocol for VPN'
  },
    {
      questionText: 'Executives at a company are concerned about employees accessing systems and information about sensitive company projects unrelated to the employees’ normal job duties. Which of the following enterprise security capabilities will the security team most likely deploy to detect that activity?',
      answerOptions: [
        { answerText: 'UBA', isCorrect: true },
        { answerText: 'EDR', isCorrect: false },
        { answerText: 'NAC', isCorrect: false },
        { answerText: 'DLP', isCorrect: false },
      ],
    explanation: 'UBA IS an IPS focused on external. EDR is an IDS focusing on internal behavior'
  },
    {
      questionText: 'Several customers want an organization to verify its security controls are operating effectively and have requested an independent opinion. Which of the following is the most efficient way to address these requests?',
      answerOptions: [
        { answerText: 'Hire a vendor to perform a penetration test', isCorrect: false },
        { answerText: 'Perform an annual self-assessment.', isCorrect: false },
        { answerText: 'Allow each client the right to audit', isCorrect: false },
        { answerText: 'Provide a third-party attestation report', isCorrect: true },
      ],
    explanation: 'Attestation in Audits ■ In internal audits, attestation evaluates organizational compliance, effectiveness of internal controls, and adherence to policies and procedures ■ In external audits, third-party entities provide attestation on financial statements, regulatory compliance, and operational efficiency ■ Attestation builds trust, enhances transparency, ensures accountability, and is essential for stakeholders in making informed decisions'
  },
    {
      questionText: 'A university employee logged on to the academic server and attempted to guess the system administrators’ log-in credentials. Which of the following security measures should the university have implemented to detect the employee’s attempts to gain access to the administrators’ accounts?',
      answerOptions: [
        { answerText: 'Two-factor authentication', isCorrect: false },
        { answerText: 'Firewall', isCorrect: false },
        { answerText: 'Intrusion prevention system', isCorrect: false },
        { answerText: 'User activity logs', isCorrect: true },
      ],
    explanation: 'User Activity logs will show when he tried to log in. They arent trying to prevent or it would be 2FA. Key word "DETECT"'
  },
    {
      questionText: 'Which of the following consequences would a retail chain most likely face from customers in the event the retailer is non-compliant with PCI DSS?',
      answerOptions: [
        { answerText: 'Contractual impacts', isCorrect: false },
        { answerText: 'Sanctions', isCorrect: false },
        { answerText: 'Fines', isCorrect: false },
        { answerText: 'Reputational damage', isCorrect: true },
      ],
    explanation: 'The question says, \'from customers\' who won\'t enforce the other options.'
  },
    {
      questionText: 'A security analyst is reviewing logs and discovers the following:Which of the following should be used to best mitigate this type of attack?',
      answerOptions: [
        { answerText: 'Input sanitization', isCorrect: true },
        { answerText: 'Secure cookies', isCorrect: false },
        { answerText: 'Static code analysis', isCorrect: false },
        { answerText: 'Sandboxing', isCorrect: false },
      ],
    explanation: 'The log entry in the image suggests that the system is potentially under attack, as the User-Agent header contains what looks like a shell command: This type of activity may indicate an attempted command injection attack, where an attacker is trying to execute shell commands via a vulnerable web application.'
  },
    {
      questionText: 'An administrator is installing an SSL certificate on a new system. During testing, errors indicate that the certificate is not trusted. The administrator has verified with the issuing CA and has validated the private key. Which of the following should the administrator check for next?',
      answerOptions: [
        { answerText: 'If the wildcard certificate is configured', isCorrect: false },
        { answerText: 'If the certificate signing request is valid', isCorrect: false },
        { answerText: 'If the root certificate is installed', isCorrect: true },
        { answerText: 'If the public key is configured', isCorrect: false },
      ],
    explanation: 'For an SSL/TLS certificate to be trusted, the system must have the root certificate (and any intermediate certificates) from the issuing Certificate Authority (CA) installed in its trusted certificate store. If the root or intermediate certificate is missing, the system will not recognize the SSL certificate as valid, leading to trust errors during testing.'
  },
    {
      questionText: 'An employee emailed a new systems administrator a malicious web link and convinced the administrator to change the email server’s password. The employee used this access to remove the mailboxes of key personnel. Which of the following security awareness concepts would help prevent this threat in the future?',
      answerOptions: [
        { answerText: 'Recognizing phishing', isCorrect: true },
        { answerText: 'Providing situational awareness training', isCorrect: false },
        { answerText: 'Using password management', isCorrect: false },
        { answerText: 'Reviewing email policies', isCorrect: false },
      ],
    explanation: 'This scenario describes a phishing attack, where the employee tricked the systems administrator into performing an action (changing the email server\'s password) by sending a malicious web link. Security awareness training that focuses on recognizing phishing attempts can help employees and administrators identify and avoid such manipulative tactics in the future. Training should include spotting suspicious links, verifying requests, and understanding social engineering techniques.'
  },
    {
      questionText: 'Which of the following strategies should an organization use to efficiently manage and analyze multiple types of logs?',
      answerOptions: [
        { answerText: 'Deploy a SIEM solution', isCorrect: true },
        { answerText: 'Create custom scripts to aggregate and analyze logs.', isCorrect: false },
        { answerText: 'Implement EDR technology.', isCorrect: false },
        { answerText: 'Install a unified threat management appliance.', isCorrect: false },
      ],
    explanation: 'SIEM helps: Log Collection and Aggregation, Alert Management, Correlation and Analysis, Reporting and Visualization, Access Control and Security.'
  },
    {
      questionText: 'A new security regulation was announced that will take effect in the coming year. A company must comply with it to remain in business. Which of the following activities should the company perform next?',
      answerOptions: [
        { answerText: 'Gap analysis', isCorrect: true },
        { answerText: 'Policy review', isCorrect: false },
        { answerText: 'Security procedure evaluation', isCorrect: false },
        { answerText: 'Threat scope reduction', isCorrect: false },
      ],
    explanation: 'Gap Analysis in Security: Compares what you have (existing security) vs what you need (required security) Shows what\'s missing Creates plan to fill the gaps Helps meet new security requirements efficiently Like a security checklist that shows: Have ✓ Need ✗ Plan to get there →'
  },
    {
      questionText: 'An accountant is transferring information to a bank over FTP. Which of the following mitigations should the accountant use to protect the confidentiality of the data?',
      answerOptions: [
        { answerText: 'Tokenization', isCorrect: false },
        { answerText: 'Data masking', isCorrect: false },
        { answerText: 'Encryption', isCorrect: true },
        { answerText: 'Obfuscation', isCorrect: false },
      ],
    explanation: 'C. Encryption Explanation: When transferring sensitive data over FTP (File Transfer Protocol), encryption is the best method to ensure the confidentiality of the data. FTP by itself does not provide any encryption, meaning that the data is transmitted in plain text, which can be intercepted by attackers.'
  },
    {
      questionText: 'An organization has recently decided to implement SSO. The requirements are to leverage access tokens and focus on application authorization rather than user authentication. Which of the following solutions would the engineering team most likely configure?',
      answerOptions: [
        { answerText: 'LDAP', isCorrect: false },
        { answerText: 'Federation', isCorrect: false },
        { answerText: 'SAML', isCorrect: false },
        { answerText: 'OAuth', isCorrect: true },
      ],
    explanation: 'For modern web applications and APIs: OAuth is preferred for authorization SAML is preferred for authentication LDAP is often used more for internal network resources and directory services'
  },
    {
      questionText: 'Which of the following would most likely be used by attackers to perform credential harvesting?',
      answerOptions: [
        { answerText: 'Social engineering', isCorrect: true },
        { answerText: 'Supply chain compromise', isCorrect: false },
        { answerText: 'Third-party software', isCorrect: false },
        { answerText: 'Rainbow table', isCorrect: false },
      ],
    explanation: 'Study Guide glossary: credential harvesting Social engineering techniques for gathering valid credentials to use to gain unauthorized access.'
  },
    {
      questionText: 'A security engineer would like to enhance the use of automation and orchestration within the SIEM. Which of the following would be the primary benefit of this enhancement?',
      answerOptions: [
        { answerText: 'It increases complexity.', isCorrect: false },
        { answerText: 'It removes technical debt.', isCorrect: false },
        { answerText: 'It adds additional guard rails.', isCorrect: false },
        { answerText: 'It acts as a workforce multiplier.', isCorrect: true },
      ],
    explanation: 'Automation and orchestration within a SIEM system allow security teams to respond to incidents more quickly and efficiently, without requiring as much manual effort for repetitive tasks. This effectively "multiplies" the workforce\'s capability, enabling a smaller team to handle more incidents or data points.'
  },
    {
      questionText: 'A systems administrator receives an alert that a company’s internal file server is very slow and is only working intermittently. The systems administrator reviews the server management software and finds the following information about the server:Which of the following indicators most likely triggered this alert?',
      answerOptions: [
        { answerText: 'Concurrent session usage', isCorrect: false },
        { answerText: 'Network saturation', isCorrect: false },
        { answerText: 'Account lockout', isCorrect: false },
        { answerText: 'Resource consumption', isCorrect: true },
      ],
    explanation: 'resource consumption'
  },
    {
      questionText: 'Which of the following data states applies to data that is being actively processed by a database server?',
      answerOptions: [
        { answerText: 'In use', isCorrect: true },
        { answerText: 'At rest', isCorrect: false },
        { answerText: 'In transit', isCorrect: false },
        { answerText: 'Being hashed', isCorrect: false },
      ],
    explanation: 'In Rest: In use: Actively being processed or used. Data is loading, editing, computation, etc. At Rest: Stored, hard drive, cloud, not used, no connection, power off the database, etc. In Transit: Over the network, between the system, data transferring, etc. Being Hashed: Relevant with security, cryptographic, hashing, integrity, etc.'
  },
    {
      questionText: 'Which of the following architectures is most suitable to provide redundancy for critical business processes?',
      answerOptions: [
        { answerText: 'Network-enabled', isCorrect: false },
        { answerText: 'Server-side', isCorrect: false },
        { answerText: 'Cloud-native', isCorrect: true },
        { answerText: 'Multitenant', isCorrect: false },
      ],
    explanation: 'Cloud-native architectures are designed to leverage the flexibility, scalability, and redundancy features of cloud environments. These architectures typically use distributed systems, microservices, and containerization (e.g., Kubernetes) to ensure high availability, fault tolerance, and automated failover. Cloud providers offer built-in redundancy and disaster recovery solutions, ensuring that critical business processes are protected from outages. Not D. Multitenant: Multitenant architectures allow multiple clients or tenants to share the same infrastructure. While they can provide efficient resource utilization, they aren\'t specifically designed for redundancy. Redundancy would still need to be implemented through other mechanisms (e.g., cloud services, clustering).'
  },
        {
      questionText: "After a security incident, a systems administrator asks the company to buy a NAC platform. Which of the following attack surfaces is the systems administrator trying to protect?",
      answerOptions: [
        { answerText: 'Bluetooth', isCorrect: false },
        { answerText: 'Wired', isCorrect: true },
        { answerText: 'NFC', isCorrect: false },
        { answerText: 'SCADA', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'While reviewing logs, a security administrator identifies the following code: `<script>alert("XSS")</script>`. Which of the following best describes the vulnerability being exploited?',
      answerOptions: [
        { answerText: 'XSS', isCorrect: true },
        { answerText: 'SQLi', isCorrect: false },
        { answerText: 'DDoS', isCorrect: false },
        { answerText: 'CSRF', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'An organization issued new laptops to all employees and wants to provide web filtering both in and out of the office without configuring additional access to the network. Which of the following types of web filtering should a systems administrator configure?',
      answerOptions: [
        { answerText: 'Agent-based', isCorrect: true },
        { answerText: 'Centralized proxy', isCorrect: false },
        { answerText: 'URL scanning', isCorrect: false },
        { answerText: 'Content categorization', isCorrect: false },
      ],
    explanation: 'Agent-based web filtering is the most suitable solution. It provides granular control over web traffic on individual devices, ensuring consistent filtering policies regardless of network location.'
  },
    {
      questionText: 'Which of the following should be used to aggregate log data in order to create alerts and detect anomalous activity?',
      answerOptions: [
        { answerText: 'SIEM', isCorrect: true },
        { answerText: 'WAF', isCorrect: false },
        { answerText: 'Network taps', isCorrect: false },
        { answerText: 'IDS', isCorrect: false },
      ],
    explanation: 'The correct answer is: A. SIEM (Security Information and Event Management) SIEM (Security Information and Event Management) systems are designed to collect, aggregate, and analyze log data from various sources such as servers, firewalls, applications, and network devices. They provide capabilities for: Creating alerts based on specific criteria. Detecting anomalous activity through correlation and behavioral analysis. Providing a centralized view of security events.'
  },
    {
      questionText: 'Which of the following provides the best protection against unwanted or insecure communications to and from a device?',
      answerOptions: [
        { answerText: 'System hardening', isCorrect: false },
        { answerText: 'Host-based firewall', isCorrect: true },
        { answerText: 'Intrusion detection system', isCorrect: false },
        { answerText: 'Anti-malware software', isCorrect: false },
      ],
    explanation: 'Host-based firewall= both detection and protection. IDS- only detection.'
  },
    {
      questionText: 'Which of the following is the primary purpose of a service that tracks log-ins and time spent using the service?',
      answerOptions: [
        { answerText: 'Availability', isCorrect: false },
        { answerText: 'Accounting', isCorrect: true },
        { answerText: 'Authentication', isCorrect: false },
        { answerText: 'Authorization', isCorrect: false },
      ],
    explanation: 'Accounting refers to tracking and recording user activities, such as log-ins and the time spent using a service. It helps in auditing, monitoring usage patterns, and ensuring compliance with usage policies. This function is crucial for resource management and analyzing how services are being used'
  },
    {
      questionText: 'An employee who was working remotely lost a mobile device containing company data. Which of the following provides the best solution to prevent future data loss?',
      answerOptions: [
        { answerText: 'MDM', isCorrect: true },
        { answerText: 'DLP', isCorrect: false },
        { answerText: 'FDE', isCorrect: false },
        { answerText: 'EDR', isCorrect: false },
      ],
    explanation: 'Full Disk Encryption (FDE) ensures that all data stored on the device is encrypted, making it inaccessible without proper authentication (such as a password or biometric verification). If the mobile device is lost or stolen, the data remains secure because it is encrypted. This helps protect sensitive company data even if the device is no longer in the employee’s possession. Not A. MDM (Mobile Device Management): While MDM is excellent for managing devices, enforcing security policies, and remotely wiping or locking a lost device, it doesn\'t directly address the encryption of data. It\'s more focused on managing device configurations and enforcing security policies.'
  },
    {
      questionText: 'An IT administrator needs to ensure data retention standards are implemented on an enterprise application. Which of the following describes the administrator’s role?',
      answerOptions: [
        { answerText: 'Processor', isCorrect: false },
        { answerText: 'Custodian', isCorrect: true },
        { answerText: 'Privacy officer', isCorrect: false },
        { answerText: 'Owner', isCorrect: false },
      ],
    explanation: 'The role of a custodian involves managing and maintaining data on behalf of the data owner. The custodian is responsible for implementing the policies and procedures related to data retention, ensuring that data is stored, archived, or disposed of according to organizational and regulatory standards.'
  },
    {
      questionText: 'A company plans to secure its systems by:\n\n• Preventing users from sending sensitive data over corporate email\n•  Restricting access to potentially harmful websites\n\n Which of the following features should the company set up? (Choose two.)',
      answerOptions: [
        { answerText: 'DLP software', isCorrect: true },
        { answerText: 'DNS filtering', isCorrect: true },
        { answerText: 'File integrity monitoring', isCorrect: false },
        { answerText: 'Stateful firewall', isCorrect: false },
        { answerText: 'Guardrails', isCorrect: false },
        { answerText: 'Antivirus signatures', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'A company processes and stores sensitive data on its own systems. Which of the following steps should the company take first to ensure compliance with privacy regulations?',
      answerOptions: [
        { answerText: 'Implement access controls and encryption.', isCorrect: true },
        { answerText: 'Develop and provide training on data protection policies.', isCorrect: false },
        { answerText: 'Create incident response and disaster recovery plans.', isCorrect: false },
        { answerText: 'Purchase and install security software.', isCorrect: false },
      ],
    explanation: 'The correct answer is: A. Implement access controls and encryption. Explanation: To ensure compliance with privacy regulations, the first step the company should take is to implement access controls and encryption. These are fundamental security measures to protect sensitive data: Access controls ensure that only authorized individuals can access sensitive data, thereby minimizing the risk of unauthorized access. Encryption protects data both at rest and in transit, ensuring that even if data is intercepted or accessed without permission, it cannot be read or used. Privacy regulations like GDPR, HIPAA, and others often have strict requirements about how sensitive data must be protected, and implementing access controls and encryption is a core component of those requirements.'
  },
    {
      questionText: 'Which of the following cryptographic methods is preferred for securing communications with limited computing resources?',
      answerOptions: [
        { answerText: 'Hashing algorithm', isCorrect: false },
        { answerText: 'Public key infrastructure', isCorrect: false },
        { answerText: 'Symmetric encryption', isCorrect: true },
        { answerText: 'Elliptic curve cryptography', isCorrect: false },
      ],
    explanation: 'From Study Guide: The drawback of asymmetric encryption is that it involves substantial computing overhead compared to symmetric encryption. Where a large amount of data is being encrypted on disk or transported over a network, asymmetric encryption is inefficient. Rather than being used to encrypt the bulk data directly, the public key cipher can be used to encrypt a symmetric secret key. The Elliptic Curve Cryptography (ECC) asymmetric cipher can use 256-bit private keys to achieve a level of security equivalent to a 3,072-bit RSA key. I think the technical correct answer is D, but exam correct answer is C.'
  },
    {
      questionText: 'A network administrator wants to ensure that network traffic is highly secure while in transit.Which of the following actions best describes the actions the network administrator should take?',
      answerOptions: [
        { answerText: 'Ensure that NAC is enforced on all network segments, and confirm that firewalls have updated policies to block unauthorized traffic.', isCorrect: false },
        { answerText: 'Ensure only TLS and other encrypted protocols are selected for use on the network, and only permit authorized traffic via secure protocols.', isCorrect: true },
        { answerText: 'Configure the perimeter IPS to block inbound HTTPS directory traversal traffic, and verify that signatures are updated on a daily basis.', isCorrect: false },
        { answerText: 'Ensure the EDR software monitors for unauthorized applications that could be used by threat actors, and configure alerts for the security team.', isCorrect: false },
      ],
    explanation: 'EDR Focus: EDR software is primarily designed to monitor and protect endpoints (e.g., laptops, desktops, servers) from threats like malware, ransomware, and unauthorized applications. It is not specifically designed to secure network traffic in transit.'
  },
    {
      questionText: 'Which of the following definitions best describes the concept of log correlation?',
      answerOptions: [
        { answerText: 'Combining relevant logs from multiple sources into one location', isCorrect: false },
        { answerText: 'Searching and processing data to identify patterns of malicious activity', isCorrect: true },
        { answerText: 'Making a record of the events that occur in the system', isCorrect: false },
        { answerText: 'Analyzing the log files of the system components', isCorrect: false },
      ],
    explanation: 'Combining Logs from Different Sources: In large environments, logs come from multiple systems such as servers, applications, firewalls, network devices, and security systems. Log correlation involves integrating and analyzing these logs togeth'
  },
    {
      questionText: 'An enterprise security team is researching a new security architecture to better protect the company’s networks and applications against the latest cyberthreats. The company has a fully remote workforce. The solution should be highly redundant and enable users to connect to a VPN with an integrated, software-based firewall. Which of the following solutions meets these requirements?',
      answerOptions: [
        { answerText: 'IPS', isCorrect: false },
        { answerText: 'SIEM', isCorrect: false },
        { answerText: 'SASE', isCorrect: true },
        { answerText: 'CASB', isCorrect: false },
      ],
    explanation: 'C. SASE (Secure Access Service Edge) Explanation: SASE is a cloud-based security architecture that integrates networking and security services, making it ideal for enterprises with a fully remote workforce. It combines VPN, software-defined networking (SD-WAN), firewall-as-a-service (FWaaS), zero-trust access, and cloud security into a single, scalable solution. Key benefits that align with the requirements: ✔ Highly redundant – SASE operates in the cloud with multiple points of presence (PoPs), ensuring availability. ✔ Integrated VPN – Secure remote access is a core feature of SASE, often replacing traditional VPNs with Zero Trust Network Access (ZTNA). ✔ Software-based firewall – SASE includes Firewall-as-a-Service (FWaaS), which integrates security policies without requiring on-premises hardware. ✔ Protection against latest cyberthreats – Uses secure web gateways (SWG), cloud access security brokers (CASB), and data loss prevention (DLP) to enforce security policies across all users and devices.'
  },
    {
      questionText: 'Which of the following is the best way to validate the integrity and availability of a disaster recovery site?',
      answerOptions: [
        { answerText: 'Lead a simulated failover.', isCorrect: true },
        { answerText: 'Conduct a tabletop exercise.', isCorrect: false },
        { answerText: 'Periodically test the generators.', isCorrect: false },
        { answerText: 'Develop requirements for database encryption.', isCorrect: false },
      ],
    explanation: 'The correct answer is: A. Lead a simulated failover. Explanation: A simulated failover is the best way to validate the integrity and availability of a disaster recovery (DR) site. This involves performing a controlled test where the operations of the primary site are intentionally interrupted (e.g., simulating a failure), and the DR site is activated to take over the workload. This ensures that the DR site is capable of handling operations as expected, providing both availability (ensuring services can continue in the event of a failure) and integrity (confirming the site has the correct, intact data and configurations).'
  },
    {
      questionText: 'Which of the following allows an exploit to go undetected by the operating system?',
      answerOptions: [
        { answerText: 'Firmware vulnerabilities', isCorrect: false },
        { answerText: 'Side loading', isCorrect: false },
        { answerText: 'Memory injection', isCorrect: true },
        { answerText: 'Encrypted payloads', isCorrect: false },
      ],
    explanation: 'The correct answer is: C. Memory injection Explanation: Memory injection involves injecting malicious code or data into the memory of a running process or the operating system itself. This type of exploit allows the attacker to bypass traditional detection methods, as the malicious code is executed directly in memory and does not necessarily touch the file system. Since it is executed in memory, it can evade detection by antivirus software or other file-based security measures, allowing the exploit to go undetected by the operating system.'
  },
    {
      questionText: 'A malicious insider from the marketing team alters records and transfers company funds to a personal account. Which of the following methods would be the best way to secure company records in the future?',
      answerOptions: [
        { answerText: 'Permission restrictions', isCorrect: true },
        { answerText: 'Hashing', isCorrect: false },
        { answerText: 'Input validation', isCorrect: false },
        { answerText: 'Access control list', isCorrect: false },
      ],
    explanation: 'While ACLs can help, permission restrictions are a broader and more effective approach for securing company records against insider threats. Permission restriction can be applied on the file, folder and drive as well, which is more effective.'
  },
    {
      questionText: 'An organization is required to provide assurance that its controls are properly designed and operating effectively. Which of the following reports will best achieve the objective?',
      answerOptions: [
        { answerText: 'Red teaming', isCorrect: false },
        { answerText: 'Penetration testing', isCorrect: false },
        { answerText: 'Independent audit', isCorrect: true },
        { answerText: 'Vulnerability assessment', isCorrect: false },
      ],
    explanation: 'An independent audit is conducted by a third-party organization or qualified external auditors to evaluate and verify that the organization’s controls are properly designed and operating effectively. It provides assurance to stakeholders (e.g., clients, regulators, or internal management) about the organization\'s adherence to standards, policies, or regulations'
  },
    {
      questionText: 'A systems administrator successfully configures VPN access to a cloud environment. Which of the following capabilities should the administrator use to best facilitate remote administration?',
      answerOptions: [
        { answerText: 'A jump host in the shared services security zone', isCorrect: true },
        { answerText: 'An SSH server within the corporate LAN', isCorrect: false },
        { answerText: 'A reverse proxy on the firewall', isCorrect: false },
        { answerText: 'An MDM solution with conditional access', isCorrect: false },
      ],
    explanation: 'SSH use for connecting to the system network, not design for cloud. A reverse proxy use for website (like websites), not for remote administration of cloud systems. It doesn’t provide a secure way for administrators to access and manage cloud resources. MDM (Mobile Device Management) is for securing and managing mobile devices, not for remote administration of cloud environments.'
  },
    {
      questionText: 'Which of the following best describes the concept of information being stored outside of its country of origin while still being subject to the laws and requirements of the country of origin?',
      answerOptions: [
        { answerText: 'Data sovereignty', isCorrect: true },
        { answerText: 'Geolocation', isCorrect: false },
        { answerText: 'Intellectual property', isCorrect: false },
        { answerText: 'Geographic restrictions', isCorrect: false },
      ],
    explanation: 'Data sovereignty refers to the concept that information stored in a different country is still subject to the laws and regulations of its country of origin. This is particularly relevant in contexts like cloud computing, where data might be stored in servers located in different jurisdictions, yet the legal obligations of the originating country (e.g., GDPR in Europe) still apply'
  },
    {
      questionText: 'An audit reveals that cardholder database logs are exposing account numbers inappropriately. Which of the following mechanisms would help limit the impact of this error?',
      answerOptions: [
        { answerText: 'Segmentation', isCorrect: false },
        { answerText: 'Hashing', isCorrect: false },
        { answerText: 'Journaling', isCorrect: false },
        { answerText: 'Masking', isCorrect: true },
      ],
    explanation: 'Masking involves obscuring or redacting sensitive data, such as account numbers, in logs or other outputs. For example, instead of logging the full account number, a masked version like XXXX-XXXX-XXXX-1234 would be logged. This reduces the exposure of sensitive data and minimizes the impact of inappropriate access or disclosure'
  },
    {
      questionText: "A security analyst attempts to start a company's database server. When the server starts, the analyst receives an error message indicating the database server did not pass authentication. After reviewing and testing the system, the analyst receives confirmation that the server has been compromised and that attackers have redirected all outgoing database traffic to a server under their control. Which of the following MITRE ATT&CK techniques did the attacker most likely use to redirect database traffic?",
      answerOptions: [
        { answerText: 'Browser extension', isCorrect: false },
        { answerText: 'Process injection', isCorrect: false },
        { answerText: 'Valid accounts', isCorrect: true },
        { answerText: 'Escape to host', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'A penetration tester enters an office building at the same time as a group of employees despite not having an access badge. Which of the following attack types is the penetration tester performing?',
      answerOptions: [
        { answerText: 'Tailgating', isCorrect: true },
        { answerText: 'Shoulder surfing', isCorrect: false },
        { answerText: 'RFID cloning', isCorrect: false },
        { answerText: 'Forgery', isCorrect: false },
      ],
    explanation: 'Obvious: A tailgating attack is a breach of security where an unauthorized actor gains access to a controlled area by closely following someone with legitimate access credentials.'
  },
    {
      questionText: 'Which of the following enables the ability to receive a consolidated report from different devices on the network?',
      answerOptions: [
        { answerText: 'IPS', isCorrect: false },
        { answerText: 'DLP', isCorrect: false },
        { answerText: 'SIEM', isCorrect: true },
        { answerText: 'Firewall', isCorrect: false },
      ],
    explanation: 'C. SIEM Explanation: A SIEM (Security Information and Event Management) system is designed to collect, aggregate, and analyze logs and data from various devices on the network, including firewalls, intrusion detection systems (IDS), servers, and more.'
  },
    {
      questionText: 'Which of the following should an organization focus on the most when making decisions about vulnerability prioritization?',
      answerOptions: [
        { answerText: 'Exposure factor', isCorrect: false },
        { answerText: 'CVSS', isCorrect: true },
        { answerText: 'CVE', isCorrect: false },
        { answerText: 'Industry impact', isCorrect: false },
      ],
    explanation: 'B. CVSS (Common Vulnerability Scoring System) The Common Vulnerability Scoring System (CVSS) provides a standardized method to evaluate and score the severity of vulnerabilities. It includes metrics such as exploitability, impact, and environmental factors, which help organizations prioritize vulnerabilities effectively based on their risk level.'
  },
    {
      questionText: 'An organization needs to monitor its users’ activities in order to prevent insider threats. Which of the following solutions would help the organization achieve this goal?',
      answerOptions: [
        { answerText: 'Behavioral analytics', isCorrect: true },
        { answerText: 'Access control lists', isCorrect: false },
        { answerText: 'Identity and access management', isCorrect: false },
        { answerText: 'Network intrusion detection system', isCorrect: false },
      ],
    explanation: 'Behavioral analytics is a technique that uses machine learning and data mining to identify anomalies in user behavior. By analyzing user activity data, such as login times, access patterns, and data transfers, behavioral analytics can detect suspicious activity that may indicate an insider threat.'
  },
    {
      questionText: "A customer of a large company receives a phone call from someone claiming to work for the company and asking for the customer’s credit card information. The customer sees the caller ID is the same as the company's main phone number. Which of the following attacks is the customer most likely a target of?",
      answerOptions: [
        { answerText: 'Phishing', isCorrect: false },
        { answerText: 'Whaling', isCorrect: false },
        { answerText: 'Smishing', isCorrect: false },
        { answerText: 'Vishing', isCorrect: true },
      ],
    explanation: ''
  },
    {
      questionText: 'A security analyst is reviewing logs to identify the destination of command-and-control traffic originating from a compromised device within the on-premises network. Which of the following is the best log to review?',
      answerOptions: [
        { answerText: 'IDS', isCorrect: false },
        { answerText: 'Antivirus', isCorrect: false },
        { answerText: 'Firewall', isCorrect: true },
        { answerText: 'Application', isCorrect: false },
      ],
    explanation: 'C. Firewall Explanation: The firewall logs are the best logs to review when trying to identify the destination of command-and-control (C2) traffic. Firewalls track inbound and outbound network traffic, including the source and destination IP addresses, ports, and protocols used.'
  },
    {
      questionText: 'When trying to access an internal website, an employee reports that a prompt displays, stating that the site is insecure. Which of the following certificate types is the site most likely using?',
      answerOptions: [
        { answerText: 'Wildcard', isCorrect: false },
        { answerText: 'Root of trust', isCorrect: false },
        { answerText: 'Third-party', isCorrect: false },
        { answerText: 'Self-signed', isCorrect: true },
      ],
    explanation: 'When an employee encounters a prompt indicating a website is insecure, it often means the browser cannot verify the authenticity of the website’s SSL/TLS certificate. This is most commonly caused by the site using a self-signed certificate, which lacks validation from a trusted Certificate Authority (CA)'
  },
    {
      questionText: 'Which of the following would most likely be deployed to obtain and analyze attacker activity and techniques?',
      answerOptions: [
        { answerText: 'Firewall', isCorrect: false },
        { answerText: 'IDS', isCorrect: false },
        { answerText: 'Honeypot', isCorrect: true },
        { answerText: 'Layer 3 switch', isCorrect: false },
      ],
    explanation: 'The correct answer is: C. Honeypot Explanation: A honeypot is a security mechanism designed to attract, detect, and analyze attacker activity by mimicking a real system or network resource. It is deliberately made vulnerable or enticing to attackers so that security teams can monitor their techniques, tools, and behavior in a controlled environment.'
  },
    {
      questionText: 'Which of the following objectives is best achieved by a tabletop exercise?',
      answerOptions: [
        { answerText: 'Familiarizing participants with the incident response process', isCorrect: true },
        { answerText: 'Deciding red and blue team rules of engagement', isCorrect: false },
        { answerText: 'Quickly determining the impact of an actual security breach', isCorrect: false },
        { answerText: 'Conducting multiple security investigations in parallel', isCorrect: false },
      ],
    explanation: 'The purpose of a tabletop exercise is to test and improve an organization\'s response to a simulated incident. They help organizations prepare for real-world incidents by identifying weaknesses and improving coordination.'
  },
    {
      questionText: 'The private key for a website was stolen, and a new certificate has been issued. Which of the following needs to be updated next?',
      answerOptions: [
        { answerText: 'SCEP', isCorrect: false },
        { answerText: 'CRL', isCorrect: true },
        { answerText: 'OCSP', isCorrect: false },
        { answerText: 'CSR', isCorrect: false },
      ],
    explanation: 'When a private key for a website is stolen, the certificate associated with that key is considered compromised. The next important step is to update the Certificate Revocation List (CRL) to include the old certificate so that clients and browsers know that it should no longer be trusted.'
  },
    {
      questionText: "Which of the following organizational documents is most often used to establish and communicate expectations associated with integrity and ethical behavior within an organization?",
      answerOptions: [
        { answerText: 'AUP', isCorrect: true },
        { answerText: 'SLA', isCorrect: false },
        { answerText: 'EULA', isCorrect: false },
        { answerText: 'MOA', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'Which of the following explains how to determine the global regulations that data is subject to regardless of the country where the data is stored?',
      answerOptions: [
        { answerText: 'Geographic dispersion', isCorrect: false },
        { answerText: 'Data sovereignty', isCorrect: true },
        { answerText: 'Geographic restrictions', isCorrect: false },
        { answerText: 'Data segmentation', isCorrect: false },
      ],
    explanation: 'Data sovereignty refers to the concept that data is subject to the laws and regulations of the country in which it is located or where it is collected, regardless of where it is stored. This principle is critical for understanding global regulations because it dictates how data must be handled to comply with specific national or regional laws. For example, the General Data Protection Regulation (GDPR) applies to personal data collected from EU citizens, even if the data is stored outside the EU'
  },
    {
      questionText: "An organization's web servers host an online ordering system. The organization discovers that the servers are vulnerable to a malicious JavaScript injection, which could allow attackers to access customer payment information. Which of the following mitigation strategies would be most effective for preventing an attack on the organization's web servers? (Choose two.)",
      answerOptions: [
        { answerText: 'Regularly updating server software and patches', isCorrect: true },
        { answerText: 'Implementing strong password policies', isCorrect: false },
        { answerText: 'Encrypting sensitive data at rest and in transit', isCorrect: false },
        { answerText: 'Utilizing a web-application firewall', isCorrect: true },
        { answerText: 'Performing regular vulnerability scans', isCorrect: false },
        { answerText: 'Removing payment information from the servers', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'Which of the following tools is best for logging and monitoring in a cloud environment?',
      answerOptions: [
        { answerText: 'IPS', isCorrect: false },
        { answerText: 'FIM', isCorrect: false },
        { answerText: 'NAC', isCorrect: false },
        { answerText: 'SIEM', isCorrect: true },
      ],
    explanation: 'A SIEM system is designed to collect, analyze, and correlate security-related data from various sources, such as logs, network traffic, and user activities, in real-time. This is critical for monitoring and detecting security incidents in a cloud environment'
  },
    {
      questionText: 'During a SQL update of a database, a temporary field that was created was replaced by an attacker in order to allow access to the system. Which of the following best describes this type of vulnerability?',
      answerOptions: [
        { answerText: 'Race condition', isCorrect: false },
        { answerText: 'Memory injection', isCorrect: false },
        { answerText: 'Malicious update', isCorrect: true },
        { answerText: 'Side loading', isCorrect: false },
      ],
    explanation: 'A malicious update refers to an attacker modifying a database or system during an update operation to introduce malicious changes.'
  },
    {
      questionText: 'A group of developers has a shared backup account to access the source code repository. Which of the following is best way to secure the backup account if there is an SSO failure?',
      answerOptions: [
        { answerText: 'RAS', isCorrect: false },
        { answerText: 'EAP', isCorrect: false },
        { answerText: 'SAML', isCorrect: false },
        { answerText: 'PAM', isCorrect: true },
      ],
    explanation: 'popular PAM tools: 1. Azure Active Directory (Azure AD) Privileged Identity Management (PIM) as part of its Microsoft Entra suite 2. Keeper 3. CyberArk, 4. BeyondTrust 5. Thycotic (now part of Delinea)'
  },
    {
      questionText: 'Which of the following elements of digital forensics should a company use if it needs to ensure the integrity of evidence?',
      answerOptions: [
        { answerText: 'Preservation', isCorrect: true },
        { answerText: 'E-discovery', isCorrect: false },
        { answerText: 'Acquisition', isCorrect: false },
        { answerText: 'Containment', isCorrect: false },
      ],
    explanation: 'Evidence preservation ○ Evidence includes both the device (e.g., laptop hard disk) and the data recovered from it ○ Perform analysis on a disk image, not the original drive, to prevent modifications or alteration'
  },
    {
      questionText: 'A company suffered a critical incident where 30GB of data was exfiltrated from the corporate network. Which of the following actions is the most efficient way to identify where the system data was exfiltrated from and what location the attacker sent the data to?',
      answerOptions: [
        { answerText: 'Analyze firewall and network logs for large amounts of outbound traffic to external IP addresses or domains.', isCorrect: true },
        { answerText: 'Analyze IPS and IDS logs to find the IP addresses used by the attacker for reconnaissance scans.', isCorrect: false },
        { answerText: 'Analyze endpoint and application logs to see whether file-sharing programs were running on the company systems.', isCorrect: false },
        { answerText: 'Analyze external vulnerability scans and automated reports to identify the systems the attacker could have exploited a remote code vulnerability.', isCorrect: false },
      ],
    explanation: 'The question is: 1. Source of the data extracted 2. The destination of the data was exported. The above both points are not possible by IPS, IDS, end point log, or vulnerability scan.'
  },
    {
      questionText: 'Which of the following describes the procedures a penetration tester must follow while conducting a test?',
      answerOptions: [
        { answerText: 'Rules of engagement', isCorrect: true },
        { answerText: 'Rules of acceptance', isCorrect: false },
        { answerText: 'Rules of understanding', isCorrect: false },
        { answerText: 'Rules of execution', isCorrect: false },
      ],
    explanation: 'The rules of engagement (RoE) outline the specific procedures, boundaries, and expectations that a penetration tester must adhere to during a penetration test. These rules are established to ensure the test is conducted ethically, legally, and effectively while avoiding unintended consequences.'
  },
    {
      questionText: 'A security analyst wants to better understand the behavior of users and devices in order to gain visibility into potential malicious activities. The analyst needs a control to detect when actions deviate from a common baseline. Which of the following should the analyst use?',
      answerOptions: [
        { answerText: 'Intrusion prevention system', isCorrect: false },
        { answerText: 'Sandbox', isCorrect: false },
        { answerText: 'Endpoint detection and response', isCorrect: true },
        { answerText: 'Antivirus', isCorrect: false },
      ],
    explanation: 'Endpoint detection and response (EDR) solutions provide continuous monitoring of endpoints (such as computers, servers, or other devices) to detect, investigate, and respond to suspicious activities. They are designed to analyze behaviors and identify deviations from normal patterns, offering visibility into potential malicious activities'
  },
    {
      questionText: 'A legal department must maintain a backup from all devices that have been shredded and recycled by a third party. Which of the following best describes this requirement?',
      answerOptions: [
        { answerText: 'Data retention', isCorrect: true },
        { answerText: 'Certification', isCorrect: false },
        { answerText: 'Sanitization', isCorrect: false },
        { answerText: 'Destruction', isCorrect: false },
      ],
    explanation: 'Keywords are "Maintain a backup" therefore retention is the correct response.'
  },
    {
      questionText: 'Which of the following can be used to compromise a system that is running an RTOS?',
      answerOptions: [
        { answerText: 'Cross-site scripting', isCorrect: false },
        { answerText: 'Memory injection', isCorrect: true },
        { answerText: 'Replay attack', isCorrect: false },
        { answerText: 'Ransomware', isCorrect: false },
      ],
    explanation: 'Memory injection is a technique that can be used to compromise a system running a real-time operating system (RTOS). By injecting malicious code into the memory of a running process, an attacker can gain unauthorized access to the system and its resources.'
  },
    {
      questionText: 'Which of the following threat actors would most likely deface the website of a high-profile music group?',
      answerOptions: [
        { answerText: 'Unskilled attacker', isCorrect: true },
        { answerText: 'Organized crime', isCorrect: false },
        { answerText: 'Nation-state', isCorrect: false },
        { answerText: 'Insider threat', isCorrect: false },
      ],
    explanation: 'Key word is Website,How do these unskilled attackers cause damage? One way is to launch a DDoS attack'
  },
    {
      questionText: 'A security architect wants to prevent employees from receiving malicious attachments by email. Which of the following functions should the chosen solution do?',
      answerOptions: [
        { answerText: 'Apply IP address reputation data.', isCorrect: false },
        { answerText: 'Tap and monitor the email feed.', isCorrect: false },
        { answerText: 'Scan email traffic inline.', isCorrect: true },
        { answerText: 'Check SPF records.', isCorrect: false },
      ],
    explanation: 'C. Scan email traffic inline. Inline scanning is the most effective method to prevent malicious attachments from reaching employees\' inboxes. By scanning emails in real-time, as they are being delivered, the security solution can identify and block malicious attachments before they reach the user\'s device. SPF records are used to verify the sender\'s identity, but they do not prevent malicious attachments'
  },
    {
      questionText: 'Which of the following activities is the first stage in the incident response process?',
      answerOptions: [
        { answerText: 'Detection', isCorrect: true },
        { answerText: 'Declaration', isCorrect: false },
        { answerText: 'Containment', isCorrect: false },
        { answerText: 'Verification', isCorrect: false },
      ],
    explanation: 'A. Detection Explanation: The first stage in the incident response process is Detection. This is the phase where an organization identifies that a security incident has occurred or is currently happening.'
  },
    {
      questionText: "Which of the following is the main consideration when a legacy system that is a critical part of a company's infrastructure cannot be replaced?",
      answerOptions: [
        { answerText: 'Resource provisioning', isCorrect: false },
        { answerText: 'Cost', isCorrect: false },
        { answerText: 'Single point of failure', isCorrect: true },
        { answerText: 'Complexity', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'Which of the following is a compensating control for providing user access to a high-risk website?',
      answerOptions: [
        { answerText: 'Enabling threat prevention features on the firewall', isCorrect: true },
        { answerText: 'Configuring a SIEM tool to capture all web traffic', isCorrect: false },
        { answerText: 'Setting firewall rules to allow traffic from any port to that destination', isCorrect: false },
        { answerText: 'Blocking that website on the endpoint protection software', isCorrect: false },
      ],
    explanation: 'A compensating control is a security measure implemented to reduce risk when the primary control cannot be applied. If users need access to a high-risk website, enabling threat prevention features on the firewall serves as a compensating control by inspecting and filtering potentially malicious traffic to and from the site.'
  },
    {
      questionText: 'An organization is implementing a COPE mobile device management policy. Which of the following should the organization include in the COPE policy? (Choose two.)',
      answerOptions: [
        { answerText: 'Remote wiping of the device', isCorrect: true },
        { answerText: 'Data encryption', isCorrect: true },
        { answerText: 'Requiring passwords with eight characters', isCorrect: false },
        { answerText: 'Data usage caps', isCorrect: false },
        { answerText: 'Employee data ownership', isCorrect: false },
        { answerText: 'Personal application store access', isCorrect: false },
      ],
    explanation: 'The correct answers are: A. Remote wiping of the device B. Data encryption Explanation: COPE (Corporate-Owned, Personally Enabled) devices are company-owned devices that employees can use for both work and personal purposes. The COPE policy must ensure that corporate data is secure while still allowing personal use of the device. A. Remote wiping of the device: This ensures that, in case of theft, loss, or termination of employment, the organization can remotely wipe sensitive corporate data. B. Data encryption: Encryption protects sensitive corporate data on the device, ensuring confidentiality even if the device is lost or compromised. Other Options: C. Requiring passwords with eight characters: While password policies are important, requiring a specific length alone is insufficient without broader authentication and security measures. D. Data usage caps: This is more related to cost control than security or policy enforcement.'
  },
    {
      questionText: 'A security administrator observed the following in a web server log while investigating an incident:"GET ../../../../etc/passwd"Which of the following attacks did the security administrator most likely see?',
      answerOptions: [
        { answerText: 'Privilege escalation', isCorrect: false },
        { answerText: 'Credential replay', isCorrect: false },
        { answerText: 'Brute force', isCorrect: false },
        { answerText: 'Directory traversal', isCorrect: true },
      ],
    explanation: ''
  },
    {
      questionText: 'An organization wants a third-party vendor to do a penetration test that targets a specific device. The organization has provided basic information about the device. Which of the following best describes this kind of penetration test?',
      answerOptions: [
        { answerText: 'Partially known environment', isCorrect: true },
        { answerText: 'Unknown environment', isCorrect: false },
        { answerText: 'Integrated', isCorrect: false },
        { answerText: 'Known environment', isCorrect: false },
      ],
    explanation: 'Code word is "basic"'
  },
    {
      questionText: 'Which of the following should a security team do first before a new web server goes live?',
      answerOptions: [
        { answerText: 'Harden the virtual host.', isCorrect: true },
        { answerText: 'Create WAF rules.', isCorrect: false },
        { answerText: 'Enable network intrusion detection.', isCorrect: false },
        { answerText: 'Apply patch management.', isCorrect: false },
      ],
    explanation: 'The correct answer is: A. Harden the virtual host. Explanation: Hardening the virtual host is the first step a security team should take before a new web server goes live. This involves securing the server by removing unnecessary services, applying secure configurations, and minimizing potential attack surfaces. Hardening ensures the server is in a secure state before it is exposed to potential threats. Create WAF rules (B) is important but should be done after the server is hardened, as the Web Application Firewall (WAF) rules depend on the server\'s configuration and applications. Enable network intrusion detection (C) is a broader network security measure and should be implemented after the server itself is secured. Apply patch management (D) is critical but is part of the ongoing maintenance process and should follow initial hardening. Thus, hardening the virtual host is the first and most critical step to ensure the web server is secure before it goes live.'
  },
    {
      questionText: 'Which of the following techniques can be used to sanitize the data contained on a hard drive while allowing for the hard drive to be repurposed?',
      answerOptions: [
        { answerText: 'Degaussing', isCorrect: false },
        { answerText: 'Drive shredder', isCorrect: false },
        { answerText: 'Retention platform', isCorrect: false },
        { answerText: 'Wipe tool', isCorrect: true },
      ],
    explanation: 'A wipe tool is software that overwrites data on a storage device multiple times, making it difficult to recover the original data. This is an effective way to sanitize a hard drive without physically destroying it, allowing it to be repurposed.'
  },
    {
      questionText: 'An attacker submits a request containing unexpected characters in an attempt to gain unauthorized access to information within the underlying systems. Which of the following best describes this attack?',
      answerOptions: [
        { answerText: 'Side loading', isCorrect: false },
        { answerText: 'Target of evaluation', isCorrect: false },
        { answerText: 'Resource reuse', isCorrect: false },
        { answerText: 'SQL injection', isCorrect: true },
      ],
    explanation: 'SQL injection is an attack where an attacker submits malicious input (e.g., unexpected characters such as \', --, or ;) in user-supplied fields with the intent of manipulating SQL queries executed by the underlying database. This type of attack can result in unauthorized access to sensitive information, database modification, or even complete database compromise'
  },
    {
      questionText: 'A security analyst has determined that a security breach would have a financial impact of $15,000 and is expected to occur twice within a three-year period. Which of the following is the ALE for this risk?',
      answerOptions: [
        { answerText: '$7,500', isCorrect: false },
        { answerText: '$10,000', isCorrect: true },
        { answerText: '$15,000', isCorrect: false },
        { answerText: '$30,000', isCorrect: false },
      ],
    explanation: 'Simpler calculation without decimals: $15,000 SLE x 2 occurrences = $30,000. $30,000 / 3 years = $10,000 ALE. Answer is B.'
  },
    {
      questionText: 'A systems administrator discovers a system that is no longer receiving support from the vendor. However, this system and its environment are critical to running the business, cannot be modified, and must stay online. Which of the following risk treatments is the most appropriate in this situation?',
      answerOptions: [
        { answerText: 'Reject', isCorrect: false },
        { answerText: 'Accept', isCorrect: true },
        { answerText: 'Transfer', isCorrect: false },
        { answerText: 'Avoid', isCorrect: false },
      ],
    explanation: 'In this scenario, the organization has no choice but to accept the risk associated with the unsupported system. The system is critical to the business, and it cannot be modified or replaced without disrupting operations. Therefore, the organization must implement additional security measures, such as regular vulnerability assessments and patching, to mitigate the risk as much as possible.'
  },
    {
      questionText: 'A company discovered its data was advertised for sale on the dark web. During the initial investigation, the company determined the data was proprietary data. Which of the following is the next step the company should take?',
      answerOptions: [
        { answerText: 'Identify the attacker’s entry methods.', isCorrect: false },
        { answerText: 'Report the breach to the local authorities.', isCorrect: false },
        { answerText: 'Notify the applicable parties of the breach.', isCorrect: true },
        { answerText: "Implement vulnerability scanning of the company's systems.", isCorrect: false },
      ],
    explanation: 'When a company discovers that proprietary data has been compromised and advertised for sale on the dark web, the next step is to notify the applicable parties of the breach. This typically includes: Internal stakeholders (e.g., management, legal, and compliance teams) to ensure they are aware of the situation. Affected individuals or entities (e.g., customers, partners, employees) who may be impacted by the data breach. Regulatory authorities (depending on the jurisdiction and nature of the breach, such as GDPR for EU residents, or similar data protection laws elsewhere) to ensure compliance with breach notification laws. Prompt notification helps mitigate the impact, provide guidance to affected parties, and ensure that any required legal or regulatory actions are taken'
  },
    {
      questionText: 'Which of the following would be the best solution to deploy a low-cost standby site that includes hardware and internet access?',
      answerOptions: [
        { answerText: 'Recovery site', isCorrect: false },
        { answerText: 'Cold site', isCorrect: false },
        { answerText: 'Hot site', isCorrect: false },
        { answerText: 'Warm site', isCorrect: true },
      ],
    explanation: 'A warm site is a cost-effective solution that provides a partially configured IT environment. It includes hardware, software, and network connections, but it may require some additional setup and configuration to become fully operational. This makes it ideal for organizations that need a quick recovery time but don\'t require immediate failover capabilities.'
  },
    {
      questionText: 'An organization needs to determine how many employees are accessing the building each day in order to configure the proper access controls. Which of the following control types best meets this requirement?',
      answerOptions: [
        { answerText: 'Detective', isCorrect: true },
        { answerText: 'Preventive', isCorrect: false },
        { answerText: 'Corrective', isCorrect: false },
        { answerText: 'Directive', isCorrect: false },
      ],
    explanation: 'Detective controls are designed to identify and detect unwanted events or behaviors. In this case, the organization needs to determine how many employees are accessing the building each day, which can be done using detective controls like access logs, badge scanners, or security cameras that monitor and record employee access.'
  },
    {
      questionText: "An organization wants to implement a secure solution for remote users. The users handle sensitive PHI on a regular basis and need to access an internally developed corporate application. Which of the following best meet the organization's security requirements? (Choose two.)",
      answerOptions: [
        { answerText: 'Local administrative password', isCorrect: false },
        { answerText: 'Perimeter network', isCorrect: false },
        { answerText: 'Jump server', isCorrect: false },
        { answerText: 'WAF', isCorrect: false },
        { answerText: 'MFA', isCorrect: true },
        { answerText: 'VPN', isCorrect: true },
      ],
    explanation: ''
  },
    {
      questionText: 'A security officer is implementing a security awareness program and is placing security-themed posters around the building and is assigning online user training. Which of the following would the security officer most likely implement?',
      answerOptions: [
        { answerText: 'Password policy', isCorrect: false },
        { answerText: 'Access badges', isCorrect: false },
        { answerText: 'Phishing campaign', isCorrect: true },
        { answerText: 'Risk assessment', isCorrect: false },
      ],
    explanation: 'A phishing campaign is a cyberattack that uses fake emails or text messages to trick people into giving away personal information or money. How to protect your organization Provide security awareness training to employees'
  },
    {
      questionText: 'A security consultant is working with a client that wants to physically isolate its secure systems. Which of the following best describes this architecture?',
      answerOptions: [
        { answerText: 'SDN', isCorrect: false },
        { answerText: 'Air gapped', isCorrect: true },
        { answerText: 'Containerized', isCorrect: false },
        { answerText: 'Highly available', isCorrect: false },
      ],
    explanation: 'An air gap is a way to provide a physical separation between devices or between networks. This might be a common way to prevent access between a secure network and an insecure network. Or you may want to have an air gap between different customer’s networks.'
  },
    {
      questionText: 'A company is in the process of migrating to cloud-based services. The company’s IT department has limited resources for migration and ongoing support. Which of the following best meets the company’s needs?',
      answerOptions: [
        { answerText: 'IPS', isCorrect: false },
        { answerText: 'WAF', isCorrect: false },
        { answerText: 'SASE', isCorrect: true },
        { answerText: 'IAM', isCorrect: false },
      ],
    explanation: 'C. SASE (Secure Access Service Edge) Explanation: SASE (Secure Access Service Edge) is a cloud-native security architecture that combines wide-area networking (WAN) capabilities with comprehensive network security features like secure web gateways, firewall-as-a-service, zero-trust network access, and more.'
  },
    {
      questionText: "An employee clicks a malicious link in an email that appears to be from the company's Chief Executive Officer. The employee's computer is infected with ransomware that encrypts the company's files. Which of the following is the most effective way for the company to prevent similar incidents in the future?",
      answerOptions: [
        { answerText: 'Security awareness training', isCorrect: true },
        { answerText: 'Database encryption', isCorrect: false },
        { answerText: 'Segmentation', isCorrect: false },
        { answerText: 'Reporting suspicious emails', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'Which of the following types of vulnerabilities is primarily caused by improper use and management of cryptographic certificates?',
      answerOptions: [
        { answerText: 'Misconfiguration', isCorrect: false },
        { answerText: 'Resource reuse', isCorrect: false },
        { answerText: 'Insecure key storage', isCorrect: true },
        { answerText: 'Weak cipher suites', isCorrect: false },
      ],
    explanation: 'C. Insecure key storage is the best answer because it specifically refers to the improper handling or storing of cryptographic keys (e.g., private keys), which can lead to serious security vulnerabilities if they are exposed or not properly protected. This is directly related to the management of cryptographic certificates. On the other hand, A. Misconfiguration is a broader term that refers to general incorrect settings or configurations in systems, and while it can involve certificates, it doesn\'t specifically address the key storage issue, which is the core concern in this question.'
  },
    {
      questionText: 'Which of the following best describe the benefits of a microservices architecture when compared to a monolithic architecture? (Choose two.)',
      answerOptions: [
        { answerText: 'Easier debugging of the system', isCorrect: false },
        { answerText: 'Reduced cost of ownership of the system', isCorrect: false },
        { answerText: 'Improved scalability of the system', isCorrect: true },
        { answerText: 'Increased compartmentalization of the system', isCorrect: true },
        { answerText: 'Stronger authentication of the system', isCorrect: false },
        { answerText: 'Reduced complexity of the system', isCorrect: false },
      ],
    explanation: 'The correct answers are: C. Improved scalability of the system D. Increased compartmentalization of the system Explanation: C. Improved scalability of the system: Microservices allow individual components to be scaled independently, providing better flexibility and resource optimization compared to scaling an entire monolithic system. D. Increased compartmentalization of the system: Microservices are designed to break down a system into smaller, independent services, improving modularity and making it easier to isolate and manage components. Other Options: A. Easier debugging of the system: Debugging can be more complex in microservices due to the distributed nature of the architecture. B. Reduced cost of ownership of the system: While microservices provide flexibility, they can increase operational costs due to the need for managing multiple services and infrastructure.'
  },
    {
      questionText: "A user's workstation becomes unresponsive and displays a ransom note demanding payment to decrypt files. Before the attack, the user opened a resume they received in a message, browsed the company's website, and installed OS updates. Which of the following is the most likely vector of this attack?",
      answerOptions: [
        { answerText: 'Spear-phishing attachment', isCorrect: true },
        { answerText: 'Watering hole', isCorrect: false },
        { answerText: 'Infected website', isCorrect: false },
        { answerText: 'Typosquatting', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'A penetration tester finds an unused Ethernet port during an on-site penetration test. Upon plugging a device into the unused port, the penetration tester notices that the machine is assigned an IP address, allowing the tester to enumerate the local network. Which of the following should an administrator implement in order to prevent this situation from happening in the future?',
      answerOptions: [
        { answerText: 'Port security', isCorrect: true },
        { answerText: 'Transport Layer Security', isCorrect: false },
        { answerText: 'Proxy server', isCorrect: false },
        { answerText: 'Security zones', isCorrect: false },
      ],
    explanation: 'Port security is a feature on network switches that restricts access to a network by limiting the devices that can connect to a specific Ethernet port. By configuring port security, administrators can: Restrict which MAC addresses are allowed on a port. Disable unused ports to prevent unauthorized access. Set up actions (e.g., shutting down the port) when a violation is detected. This would prevent an unauthorized device from connecting to an unused Ethernet port and gaining access to the network'
  },
    {
      questionText: "Which of the following should be used to ensure an attacker is unable to read the contents of a mobile device's drive if the device is lost?",
      answerOptions: [
        { answerText: 'TPM', isCorrect: false },
        { answerText: 'ECC', isCorrect: false },
        { answerText: 'FDE', isCorrect: true },
        { answerText: 'HSM', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'A security administrator documented the following records during an assessment of network services:Two weeks later, the administrator performed a log review and noticed the records were changed as follows:When consulting the service owner, the administrator validated that the new address was not part of the company network. Which of the following was the company most likely experiencing?',
      answerOptions: [
        { answerText: 'DDoS attack', isCorrect: false },
        { answerText: 'DNS poisoning', isCorrect: true },
        { answerText: 'Ransomware compromise', isCorrect: false },
        { answerText: 'Spyware infection', isCorrect: false },
      ],
    explanation: 'B. DNS poisoning DNS poisoning (or DNS spoofing) occurs when an attacker alters DNS records to redirect traffic to malicious sites. In this scenario, the security administrator noticed that the network service records had been changed to an address outside the company network, indicating unauthorized modification of DNS entries. Why the other options are incorrect: • A. DDoS attack – A Distributed Denial-of-Service (DDoS) attack overwhelms a system with traffic but does not typically change DNS records. • C. Ransomware compromise – Ransomware encrypts data and demands payment but does not alter DNS records. • D. Spyware infection – Spyware collects information covertly but does not modify network service records.'
  },
    {
      questionText: 'Which of the following is the primary reason why false negatives on a vulnerability scan should be a concern?',
      answerOptions: [
        { answerText: 'The system has vulnerabilities that are not being detected.', isCorrect: true },
        { answerText: 'The time to remediate vulnerabilities that do not exist is excessive.', isCorrect: false },
        { answerText: 'Vulnerabilities with a lower severity will be prioritized over critical vulnerabilities.', isCorrect: false },
        { answerText: 'The system has vulnerabilities, and a patch has not yet been released.', isCorrect: false },
      ],
    explanation: 'A false negative in a vulnerability scan occurs when a scan fails to identify existing vulnerabilities. This is a significant concern because undetected vulnerabilities leave the system exposed to potential exploitation. If vulnerabilities are not detected, they cannot be addressed, leaving the organization at risk of attack'
  },
    {
      questionText: 'A company is concerned about theft of client data from decommissioned laptops. Which of the following is the most cost-effective method to decrease this risk?',
      answerOptions: [
        { answerText: 'Wiping', isCorrect: true },
        { answerText: 'Recycling', isCorrect: false },
        { answerText: 'Shredding', isCorrect: false },
        { answerText: 'Deletion', isCorrect: false },
      ],
    explanation: 'Wiping. You can simply use a wiping tool on your computer. It is more cost affective than using a shredder which would have been my second choice.'
  },
    {
      questionText: 'A company that has a large IT operation is looking to better control, standardize, and lower the time required to build new servers. Which of the following architectures will best achieve the company’s objectives?',
      answerOptions: [
        { answerText: 'IoT', isCorrect: false },
        { answerText: 'IaC', isCorrect: true },
        { answerText: 'IaaS', isCorrect: false },
        { answerText: 'ICS', isCorrect: false },
      ],
    explanation: 'The correct answer is: B. IaC (Infrastructure as Code) Explanation: IaC (Infrastructure as Code) allows IT teams to automate the provisioning, configuration, and management of servers using code. This ensures consistency, reduces manual errors, and significantly lowers the time needed to build new servers by automating the entire process. It is particularly beneficial for large IT operations, as it enables standardization and version control, making deployments faster and more reliable. Other Options: A. IoT (Internet of Things): IoT refers to interconnected devices and sensors, which is unrelated to server provisioning. C. IaaS (Infrastructure as a Service): While IaaS provides virtualized resources, it does not inherently standardize or automate the provisioning process without IaC tools. D. ICS (Industrial Control System): ICS is used for managing industrial processes and is not relevant to building and managing servers.'
  },
    {
      questionText: "A government official receives a blank envelope containing photos and a note instructing the official to wire a large sum of money by midnight to prevent the photos from being leaked on the internet. Which of the following best describes the threat actor's intent?",
      answerOptions: [
        { answerText: 'Organized crime', isCorrect: false },
        { answerText: 'Philosophical beliefs', isCorrect: false },
        { answerText: 'Espionage', isCorrect: false },
        { answerText: 'Blackmail', isCorrect: true },
      ],
    explanation: ''
  },
    {
      questionText: 'Which of the following is the best security reason for closing service ports that are not needed?',
      answerOptions: [
        { answerText: 'To mitigate risks associated with unencrypted traffic', isCorrect: false },
        { answerText: 'To eliminate false positives from a vulnerability scan', isCorrect: false },
        { answerText: "To reduce a system's attack surface", isCorrect: true },
        { answerText: "To improve a system's resource utilization", isCorrect: false },
      ],
    explanation: 'A system\'s attack surface refers to all the points or areas where an attacker could try to break into or exploit the system. This includes open ports, services, software, user accounts, and any other features that could be targeted.'
  },
    {
      questionText: 'Which of the following would a security administrator use to comply with a secure baseline during a patch update?',
      answerOptions: [
        { answerText: 'Information security policy', isCorrect: false },
        { answerText: 'Service-level expectations', isCorrect: false },
        { answerText: 'Standard operating procedure', isCorrect: true },
        { answerText: 'Test result report', isCorrect: false },
      ],
    explanation: 'A Standard Operating Procedure (SOP) provides detailed, step-by-step instructions on how to perform specific tasks or operations, such as patch updates. It ensures that patch updates are done consistently and securely, in line with the organization\'s established secure baseline.'
  },
    {
      questionText: "A malicious actor conducted a brute-force attack on a company's web servers and eventually gained access to the company's customer information database. Which of the following is the most effective way to prevent similar attacks?",
      answerOptions: [
        { answerText: 'Regular patching of servers', isCorrect: false },
        { answerText: 'Web application firewalls', isCorrect: false },
        { answerText: 'Multifactor authentication', isCorrect: true },
        { answerText: 'Enabling encryption of customer data', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'Which of the following options will provide the lowest RTO and RPO for a database?',
      answerOptions: [
        { answerText: 'Snapshots', isCorrect: false },
        { answerText: 'On-site backups', isCorrect: false },
        { answerText: 'Journaling', isCorrect: false },
        { answerText: 'Hot site', isCorrect: true },
      ],
    explanation: 'A hot site is a fully operational and continuously updated replica of the primary site, including servers, data, and applications. It allows for the quickest recovery (lowest RTO, Recovery Time Objective) and the least data loss (lowest RPO, Recovery Point Objective) because the data is synchronized in near real-time with the primary site. If the primary site fails, operations can resume almost immediately from the hot site'
  },
    {
      questionText: 'Which of the following is a possible consequence of a VM escape?',
      answerOptions: [
        { answerText: 'Malicious instructions can be inserted into memory and give the attacker elevated permissions.', isCorrect: false },
        { answerText: 'An attacker can access the hypervisor and compromise other VMs.', isCorrect: true },
        { answerText: 'Unencrypted data can be read by a user who is in a separate environment.', isCorrect: false },
        { answerText: 'Users can install software that is not on the manufacturer’s approved list.', isCorrect: false },
      ],
    explanation: 'VM Escape: This occurs when an attacker breaks out of a virtual machine (VM) and gains access to the hypervisor, which manages multiple VMs. This can lead to the compromise of other VMs running on the same hypervisor, allowing the attacker to potentially access sensitive data or disrupt services across multiple virtual environments'
  },
    {
      questionText: 'A security team at a large, global company needs to reduce the cost of storing data used for performing investigations. Which of the following types of data should have its retention length reduced?',
      answerOptions: [
        { answerText: 'Packet capture', isCorrect: true },
        { answerText: 'Endpoint logs', isCorrect: false },
        { answerText: 'OS security logs', isCorrect: false },
        { answerText: 'Vulnerability scan', isCorrect: false },
      ],
    explanation: 'This is the most detailed type of network data, capturing all traffic on a network segment. It can quickly accumulate large volumes of data, making it the most expensive to store, especially when considering long retention periods'
  },
    {
      questionText: "Which of the following is a type of vulnerability that involves inserting scripts into web-based applications in order to take control of the client's web browser?",
      answerOptions: [
        { answerText: 'SQL injection', isCorrect: false },
        { answerText: 'Cross-site scripting', isCorrect: true },
        { answerText: 'Zero-day exploit', isCorrect: false },
        { answerText: 'On-path attack', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'While investigating a possible incident, a security analyst discovers the following:Which of the following should the analyst do first?',
      answerOptions: [
        { answerText: 'Implement a WAF.', isCorrect: false },
        { answerText: 'Disable the query.php script.', isCorrect: false },
        { answerText: 'Block brute-force attempts on temporary users.', isCorrect: false },
        { answerText: 'Check the users table for new accounts.', isCorrect: true },
      ],
    explanation: 'D. Check the users table for new accounts. Here\'s why: SQL injection can lead to unauthorized database access and modifications, such as creating new user accounts. By checking the users table for any suspicious or unauthorized accounts, the analyst can quickly identify if the attack succeeded and take immediate action to remove or disable those accounts.'
  },
    {
      questionText: "Due to a cyberattack, a company's IT systems were not operational for an extended period of time. The company wants to measure how quickly the systems must be restored in order to minimize business disruption. Which of the following would the company most likely use?",
      answerOptions: [
        { answerText: 'Recovery point objective', isCorrect: false },
        { answerText: 'Risk appetite', isCorrect: false },
        { answerText: 'Risk tolerance', isCorrect: false },
        { answerText: 'Recovery time objective', isCorrect: true },
        { answerText: 'Mean time between failure', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'Which of the following actors attacking an organization is the most likely to be motivated by personal beliefs?',
      answerOptions: [
        { answerText: 'Nation-state', isCorrect: false },
        { answerText: 'Organized crime', isCorrect: false },
        { answerText: 'Hacktivist', isCorrect: true },
        { answerText: 'Insider threat', isCorrect: false },
      ],
    explanation: 'Hacktivist motivation is usually their ideological beliefs.'
  },
    {
      questionText: 'Which of the following should a security team use to document persistent vulnerabilities with related recommendations?',
      answerOptions: [
        { answerText: 'Audit report', isCorrect: false },
        { answerText: 'Risk register', isCorrect: true },
        { answerText: 'Compliance report', isCorrect: false },
        { answerText: 'Penetration test', isCorrect: false },
      ],
    explanation: 'A risk register is a document used by organizations to track and manage risks, including persistent vulnerabilities. It typically includes details about identified risks, their potential impact, likelihood, and related recommendations for mitigation or management.'
  },
    {
      questionText: 'An organization purchased a critical business application containing sensitive data. The organization would like to ensure that the application is not exploited by common data exfiltration attacks. Which of the following approaches would best help to fulfill this requirement?',
      answerOptions: [
        { answerText: 'URL scanning', isCorrect: false },
        { answerText: 'WAF', isCorrect: true },
        { answerText: 'Reverse proxy', isCorrect: false },
        { answerText: 'NAC', isCorrect: false },
      ],
    explanation: 'A WAF is specifically designed to protect web applications from a variety of attacks, including data exfiltration attempts.'
  },
    {
      questionText: 'A company wants to improve the availability of its application with a solution that requires minimal effort in the event a server needs to be replaced or added. Which of the following would be the best solution to meet these objectives?',
      answerOptions: [
        { answerText: 'Load balancing', isCorrect: true },
        { answerText: 'Fault tolerance', isCorrect: false },
        { answerText: 'Proxy servers', isCorrect: false },
        { answerText: 'Replication', isCorrect: false },
      ],
    explanation: 'Replication is the correct answer. Where it says in the event that it needs to be replaced or added is key here. Replication will allow for easy switch over in the event something happens to primary servers.'
  },
    {
      questionText: 'A company is performing a risk assessment on new software the company plans to use. Which of the following should the company assess during this process?',
      answerOptions: [
        { answerText: 'Software vulnerabilities', isCorrect: true },
        { answerText: 'Cost-benefit analysis', isCorrect: false },
        { answerText: 'Ongoing monitoring strategies', isCorrect: false },
        { answerText: 'Network infrastructure compatibility', isCorrect: false },
      ],
    explanation: 'When performing a risk assessment on new software, it’s crucial to evaluate its security vulnerabilities'
  },
    {
      questionText: "A malicious actor is trying to access sensitive financial information from a company's database by intercepting and reusing log-in credentials. Which of the following attacks is the malicious actor attempting?",
      answerOptions: [
        { answerText: 'SQL injection', isCorrect: false },
        { answerText: 'On-path', isCorrect: true },
        { answerText: 'Brute-force', isCorrect: false },
        { answerText: 'Password spraying', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: "A new employee accessed an unauthorized website. An investigation found that the employee violated the company's rules. Which of the following did the employee violate?",
      answerOptions: [
        { answerText: 'MOU', isCorrect: false },
        { answerText: 'AUP', isCorrect: true },
        { answerText: 'NDA', isCorrect: false },
        { answerText: 'MOA', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'A systems administrator is reviewing the VPN logs and notices that during non-working hours a user is accessing the company file server and information is being transferred to a suspicious IP address. Which of the following threats is most likely occurring?',
      answerOptions: [
        { answerText: 'Typosquatting', isCorrect: false },
        { answerText: 'Root or trust', isCorrect: false },
        { answerText: 'Data exfiltration', isCorrect: true },
        { answerText: 'Blackmail', isCorrect: false },
      ],
    explanation: 'This type of threat involves unauthorized data access and transfer, often performed by malicious insiders or compromised accounts.'
  },
    {
      questionText: "A company discovers suspicious transactions that were entered into the company's database and attached to a user account that was created as a trap for malicious activity. Which of the following is the user account an example of?",
      answerOptions: [
        { answerText: 'Honeytoken', isCorrect: true },
        { answerText: 'Honeynet', isCorrect: false },
        { answerText: 'Honeypot', isCorrect: false },
        { answerText: 'Honeyfile', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'A network engineer is increasing the overall security of network devices and needs to harden the devices. Which of the following will best accomplish this task?',
      answerOptions: [
        { answerText: 'Configuring centralized logging', isCorrect: false },
        { answerText: 'Generating local administrator accounts', isCorrect: false },
        { answerText: 'Replacing Telnet with SSH', isCorrect: true },
        { answerText: 'Enabling HTTP administration', isCorrect: false },
      ],
    explanation: 'SSH is a secure protocol.'
  },
    {
      questionText: "A company's accounting department receives an urgent payment message from the company's bank domain with instructions to wire transfer funds. The sender requests that the transfer be completed as soon as possible. Which of the following attacks is described?",
      answerOptions: [
        { answerText: 'Business email compromise', isCorrect: true },
        { answerText: 'Vishing', isCorrect: false },
        { answerText: 'Spear phishing', isCorrect: false },
        { answerText: 'Impersonation', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: "A company filed a complaint with its IT service provider after the company discovered the service provider's external audit team had access to some of the company's confidential information. Which of the following is the most likely reason the company filed the complaint?",
      answerOptions: [
        { answerText: 'The MOU had basic clauses from a template.', isCorrect: false },
        { answerText: 'A SOW had not been agreed to by the client.', isCorrect: false },
        { answerText: 'A WO had not been mutually approved.', isCorrect: false },
        { answerText: 'A required NDA had not been signed.', isCorrect: true },
      ],
    explanation: ''
  },
    {
      questionText: 'Which of the following aspects of the data management life cycle is most directly impacted by local and international regulations?',
      answerOptions: [
        { answerText: 'Destruction', isCorrect: false },
        { answerText: 'Certification', isCorrect: false },
        { answerText: 'Retention', isCorrect: true },
        { answerText: 'Sanitization', isCorrect: false },
      ],
    explanation: 'Data retention includes local and international: Regulations, Policies, Compliances, Disposal and Deletion, Data Security, Data Access Control, Data Storage, etc.'
  },
    {
      questionText: 'An analyst is reviewing job postings to ensure sensitive company information is not being shared with the general public. Which of the following is the analyst most likely looking for?',
      answerOptions: [
        { answerText: 'Office addresses', isCorrect: false },
        { answerText: 'Software versions', isCorrect: true },
        { answerText: 'List of board members', isCorrect: false },
        { answerText: 'Government identification numbers', isCorrect: false },
      ],
    explanation: 'When reviewing job postings, an analyst is most likely looking for information that could inadvertently expose the company\'s vulnerabilities or security posture. Posting software versions could reveal outdated or vulnerable systems, which attackers might exploit.'
  },
    {
      questionText: "An engineer has ensured that the switches are using the latest OS, the servers have the latest patches, and the endpoints' definitions are up to date. Which of the following will these actions most effectively prevent?",
      answerOptions: [
        { answerText: 'Zero-day attacks', isCorrect: false },
        { answerText: 'Insider threats', isCorrect: false },
        { answerText: 'End-of-life support', isCorrect: false },
        { answerText: 'Known exploits', isCorrect: true },
      ],
    explanation: ''
  },
    {
      questionText: 'Which of the following is most likely a security concern when installing and using low-cost IoT devices in infrastructure environments?',
      answerOptions: [
        { answerText: 'Country of origin', isCorrect: false },
        { answerText: 'Device responsiveness', isCorrect: false },
        { answerText: 'Ease of deployment', isCorrect: false },
        { answerText: 'Storage of data', isCorrect: true },
      ],
    explanation: 'From CompTIA guide: The sheer volume of data generated by IoT devices can make securing and protecting sensitive information difficult. As more devices are connected to the Internet, there is an increasing risk of data breaches and cyberattacks, which can result in the theft of personal and sensitive data. A- does not make sense. B&C are not security concerns but rather performance concerns.'
  },
    {
      questionText: 'A company captures log-in details and reviews them each week to identify conditions such as excessive log-in attempts and frequent lockouts. Which of the following should a security analyst recommend to improve security compliance monitoring?',
      answerOptions: [
        { answerText: 'Including the date and person who reviewed the information in a report', isCorrect: false },
        { answerText: 'Adding automated alerting when anomalies occur', isCorrect: true },
        { answerText: 'Requiring a statement each week that no exceptions were noted', isCorrect: false },
        { answerText: 'Masking the username in a report to protect privacy', isCorrect: false },
      ],
    explanation: 'Automated alerting is a significant improvement. Instead of relying on weekly manual reviews, automated systems can detect and alert the team immediately when unusual activity (like excessive log-in attempts or lockouts) occurs. This speeds up the response and strengthens compliance.'
  },
    {
      questionText: 'A security team is in the process of hardening the network against externally crafted malicious packets. Which of the following is the most secure method to protect the internal network?',
      answerOptions: [
        { answerText: 'Anti-malware solutions', isCorrect: false },
        { answerText: 'Host-based firewalls', isCorrect: false },
        { answerText: 'Intrusion prevention systems', isCorrect: true },
        { answerText: 'Network access control', isCorrect: false },
        { answerText: 'Network allow list', isCorrect: false },
      ],
    explanation: 'E. Network allow list Here’s why: • A network allow list (also known as a whitelist) ensures that only trusted sources or specific IP addresses are allowed to send traffic to the internal network. This approach effectively blocks all untrusted external traffic, which directly prevents malicious packets from entering the network in the first place.'
  },
    {
      questionText: "Which of the following is the best way to prevent an unauthorized user from plugging a laptop into an employee's phone network port and then using tools to scan for database servers?",
      answerOptions: [
        { answerText: 'MAC filtering', isCorrect: true },
        { answerText: 'Segmentation', isCorrect: false },
        { answerText: 'Certification', isCorrect: false },
        { answerText: 'Isolation', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: "Which of the following should a systems administrator use to decrease the company's hardware attack surface?",
      answerOptions: [
        { answerText: 'Replication', isCorrect: false },
        { answerText: 'Isolation', isCorrect: false },
        { answerText: 'Centralization', isCorrect: false },
        { answerText: 'Virtualization', isCorrect: true },
      ],
    explanation: ''
  },
    {
      questionText: 'A company wants to add an MFA solution for all employees who access the corporate network remotely. Log-in requirements include something you know, are, and have. The company wants a solution that does not require purchasing third-party applications or specialized hardware. Which of the following MFA solutions would best meet the company\'s requirements?',
      answerOptions: [
        { answerText: 'Smart card with PIN and password', isCorrect: false },
        { answerText: 'Security questions and a one-time passcode sent via email', isCorrect: false },
        { answerText: 'Voice and fingerprint verification with an SMS one-time passcode', isCorrect: false },
        { answerText: 'Mobile application-generated, one-time passcode with facial recognition', isCorrect: true },
      ],
    explanation: ''
  },
    {
      questionText: 'A company is using a legacy FTP server to transfer financial data to a third party. The legacy system does not support SFTP, so a compensating control is needed to protect the sensitive, financial data in transit. Which of the following would be the most appropriate for the company to use?',
      answerOptions: [
        { answerText: 'Telnet connection', isCorrect: false },
        { answerText: 'SSH tunneling', isCorrect: true },
        { answerText: 'Patch installation', isCorrect: false },
        { answerText: 'Full disk encryption', isCorrect: false },
      ],
    explanation: 'Since the legacy FTP server does not support SFTP, SSH tunneling can be used as a compensating control to secure the FTP traffic. SSH tunneling allows you to encrypt the traffic between the client and the server, effectively creating a secure, encrypted channel for the FTP data to be transferred over.'
  },
    {
      questionText: 'A security manager wants to reduce the number of steps required to identify and contain basic threats. Which of the following will help achieve this goal?',
      answerOptions: [
        { answerText: 'SOAR', isCorrect: true },
        { answerText: 'SIEM', isCorrect: false },
        { answerText: 'DMARC', isCorrect: false },
        { answerText: 'NIDS', isCorrect: false },
      ],
    explanation: 'How SOAR helps reduce the number of steps: Automation: Automates many manual steps in the incident response process, such as threat intelligence gathering, vulnerability scanning, and remediation actions. Orchestration: Connects and integrates various security tools and systems, enabling coordinated responses to security incidents. Centralized view: Provides a centralized view of security events across the organization, allowing security teams to quickly identify and prioritize threats. By automating and streamlining security operations, SOAR can significantly reduce the number of steps required to identify and contain basic threats, allowing security teams to respond more quickly and effectively to incidents.'
  },
    {
      questionText: "The Chief Information Officer (CIO) asked a vendor to provide documentation detailing the specific objectives within the compliance framework that the vendor's services meet. The vendor provided a report and a signed letter stating that the services meet 17 of the 21 objectives. Which of the following did the vendor provide to the CIO?",
      answerOptions: [
        { answerText: 'Penetration test results', isCorrect: false },
        { answerText: 'Self-assessment findings', isCorrect: false },
        { answerText: 'Attestation of compliance', isCorrect: true },
        { answerText: 'Third-party audit report', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'Which of the following describes the most effective way to address OS vulnerabilities after they are identified?',
      answerOptions: [
        { answerText: 'Endpoint protection', isCorrect: false },
        { answerText: 'Removal of unnecessary software', isCorrect: false },
        { answerText: 'Configuration enforcement', isCorrect: false },
        { answerText: 'Patching', isCorrect: true },
      ],
    explanation: 'Patching is the most effective way to address operating system (OS) vulnerabilities after they are identified. It involves applying updates and fixes provided by the software or OS vendor to correct known vulnerabilities. Patches often address security weaknesses that could be exploited by attackers, thus directly mitigating risks associated with those vulnerabilities.'
  },
    {
      questionText: 'The management team reports that employees are missing features on company-provided tablets, which is causing productivity issues. The management team directs the IT team to resolve the issue within 48 hours. Which of the following would be the best solution for the IT team to leverage in this scenario?',
      answerOptions: [
        { answerText: 'EDR', isCorrect: false },
        { answerText: 'COPE', isCorrect: false },
        { answerText: 'MDM', isCorrect: true },
        { answerText: 'FDE', isCorrect: false },
      ],
    explanation: 'C. MDM (Mobile Device Management) Explanation: Mobile Device Management (MDM) systems allow IT teams to remotely manage, configure, and update company-provided devices, including adding missing features, updating software, and troubleshooting issues. MDM is the best solution for resolving productivity issues with tablets within the 48-hour deadline. Why not the other options? A. EDR (Endpoint Detection and Response): Focuses on detecting and responding to security threats, not managing device features. B. COPE (Corporate-Owned, Personally Enabled): Refers to a policy for managing corporate devices but does not directly address resolving feature issues. D. FDE (Full Disk Encryption): Focuses on securing device data but does not provide device management or feature configuration capabilities.'
  },
    {
      questionText: 'A company is implementing a policy to allow employees to use their personal equipment for work. However, the company wants to ensure that only company-approved applications can be installed. Which of the following addresses this concern?',
      answerOptions: [
        { answerText: 'MDM', isCorrect: true },
        { answerText: 'Containerization', isCorrect: false },
        { answerText: 'DLP', isCorrect: false },
        { answerText: 'FIM', isCorrect: false },
      ],
    explanation: 'A. MDM (Mobile Device Management) Explanation: MDM solutions allow organizations to enforce application policies on personal devices (as part of a BYOD policy). With MDM, the company can ensure that only approved applications are installed and used for work purposes. MDM provides application control, policy enforcement, and device monitoring to maintain security while allowing personal devices. Why not the other options? B. Containerization: While it isolates work applications and data from personal ones, it does not inherently restrict which apps can be installed on the device as a whole. C. DLP (Data Loss Prevention): Focuses on preventing unauthorized access or transmission of sensitive data, but it does not control application installations. D. FIM (File Integrity Monitoring): Tracks and monitors changes to files or systems for security purposes but is unrelated to application management.'
  },
    {
      questionText: 'An alert references attacks associated with a zero-day exploit. An analyst places a bastion host in the network to reduce the risk of the exploit. Which of the following types of controls is the analyst implementing?',
      answerOptions: [
        { answerText: 'Compensating', isCorrect: true },
        { answerText: 'Detective', isCorrect: false },
        { answerText: 'Operational', isCorrect: false },
        { answerText: 'Physical', isCorrect: false },
      ],
    explanation: 'A compensating control is a security measure implemented to mitigate risk when the primary control (such as a patch for a zero-day exploit) is not available or cannot be applied immediately.'
  },
    {
      questionText: 'A penetration test has demonstrated that domain administrator accounts were vulnerable to pass-the-hash attacks. Which of the following would have been the best strategy to prevent the threat actor from using domain administrator accounts?',
      answerOptions: [
        { answerText: 'Audit each domain administrator account weekly for password compliance.', isCorrect: false },
        { answerText: 'Implement a privileged access management solution.', isCorrect: true },
        { answerText: 'Create IDS policies to monitor domain controller access.', isCorrect: false },
        { answerText: 'Use Group Policy to enforce password expiration.', isCorrect: false },
      ],
    explanation: 'The Key word prevent the threat, so it should be option B.'
  },
    {
      questionText: 'Which of the following is an example of memory injection?',
      answerOptions: [
        { answerText: 'Two processes access the same variable, allowing one to cause a privilege escalation.', isCorrect: false },
        { answerText: 'A process receives an unexpected amount of data, which causes malicious code to be executed.', isCorrect: false },
        { answerText: 'Malicious code is copied to the allocated space of an already running process.', isCorrect: true },
        { answerText: 'An executable is overwritten on the disk, and malicious code runs the next time it is executed.', isCorrect: false },
      ],
    explanation: 'C. Malicious code is copied to the allocated space of an already running process. Explanation: Memory injection occurs when malicious code is directly injected into the memory space of an already running process. This type of attack bypasses the need to write malicious code to disk, making it harder to detect with traditional file-based antivirus solutions. Examples include DLL injection or process hollowing. Why not the other options? A. Two processes access the same variable, allowing one to cause a privilege escalation: This describes a race condition, not memory injection. B. A process receives an unexpected amount of data, which causes malicious code to be executed: This describes a buffer overflow, which is a precursor to injection attacks but not memory injection itself.'
  },
    {
      questionText: 'A security administrator is implementing encryption on all hard drives in an organization. Which of the following security concepts is the administrator applying?',
      answerOptions: [
        { answerText: 'Integrity', isCorrect: false },
        { answerText: 'Authentication', isCorrect: false },
        { answerText: 'Zero Trust', isCorrect: false },
        { answerText: 'Confidentiality', isCorrect: true },
      ],
    explanation: 'By implementing encryption on all hard drives, the security administrator is ensuring that data stored on the drives remains confidential. Encryption protects data from unauthorized access by converting it into a secure format that can only be read by someone with the appropriate decryption key.'
  },
    {
      questionText: 'An administrator has configured a quarantine subnet for all guest devices that connect to the network. Which of the following would be best for the security team to perform before allowing access to corporate resources?',
      answerOptions: [
        { answerText: 'Device fingerprinting', isCorrect: false },
        { answerText: 'Compliance attestation', isCorrect: true },
        { answerText: 'Penetration test', isCorrect: false },
        { answerText: 'Application vulnerability test', isCorrect: false },
      ],
    explanation: 'Complince Attestation: Guest devices have to meet the minimum requirement for the company. The requirement includes an up-to-date OS patch, applications that are downloaded to have a security patch, a configured firewall, a device name that meets company standards, etc.'
  },
    {
      questionText: 'A customer has a contract with a CSP and wants to identify which controls should be implemented in the IaaS enclave. Which of the following is most likely to contain this information?',
      answerOptions: [
        { answerText: 'Statement of work', isCorrect: false },
        { answerText: 'Responsibility matrix', isCorrect: true },
        { answerText: 'Service-level agreement', isCorrect: false },
        { answerText: 'Master service agreement', isCorrect: false },
      ],
    explanation: 'its asking for which controls not who implements them. The SLA is for the HOW and RM is for the WHO.'
  },
    {
      questionText: 'A Chief Information Security Officer is developing procedures to guide detective and corrective activities associated with common threats, including phishing, social engineering, and business email compromise. Which of the following documents would be most relevant to revise as part of this process?',
      answerOptions: [
        { answerText: 'SDLC', isCorrect: false },
        { answerText: 'IRP', isCorrect: true },
        { answerText: 'BCP', isCorrect: false },
        { answerText: 'AUP', isCorrect: false },
      ],
    explanation: 'If you know the abbreviations of the options, you definitely find the answer. A. SDLC (Software Development Life Cycle) B. IRP (Incident Response Plan) C. BCP (Business Continuity Plan) D. AUP (Acceptable Use Policy)'
  },
    {
      questionText: 'Which of the following testing techniques uses both defensive and offensive testing methodologies with developers to securely build key applications and software?',
      answerOptions: [
        { answerText: 'Blue', isCorrect: false },
        { answerText: 'Yellow', isCorrect: true },
        { answerText: 'Red', isCorrect: false },
        { answerText: 'Green', isCorrect: false },
      ],
    explanation: 'B. Yellow Explanation: The Yellow Team is a relatively newer concept in cybersecurity testing that combines both defensive (Blue Team) and offensive (Red Team) methodologies. This team works with developers to securely build key applications and software by integrating security practices throughout the development lifecycle, also known as Secure Development Lifecycle (SDLC). Their focus is on proactively addressing vulnerabilities while also testing the application for security flaws from an attacker\'s perspective. Why not the other options? C. Red Team: The Red Team conducts offensive testing by simulating real-world attacks to identify vulnerabilities and weaknesses. They don\'t directly engage with developers to build secure applications; they focus on penetration testing and exploitation.'
  },
    {
      questionText: 'An administrator wants to automate an account permissions update for a large number of accounts. Which of the following would best accomplish this task?',
      answerOptions: [
        { answerText: 'Security groups', isCorrect: false },
        { answerText: 'Federation', isCorrect: false },
        { answerText: 'User provisioning', isCorrect: true },
        { answerText: 'Vertical scaling', isCorrect: false },
      ],
    explanation: 'Federation is primarily used for enabling single sign-on (SSO) and identity management across multiple systems, domains, organizations, etc. User provisioning tools (e.g., Azure AD, Okta, OneLogin, Ping Identity, IAM system, etc.) can automate the process.'
  },
    {
      questionText: "Which of the following is the fastest and most cost-effective way to confirm a third-party supplier's compliance with security obligations?",
      answerOptions: [
        { answerText: 'Attestation report', isCorrect: true },
        { answerText: 'Third-party audit', isCorrect: false },
        { answerText: 'Vulnerability assessment', isCorrect: false },
        { answerText: 'Penetration testing', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: 'Various company stakeholders meet to discuss roles and responsibilities in the event of a security breach that would affect offshore offices. Which of the following is this an example of?',
      answerOptions: [
        { answerText: 'Tabletop exercise', isCorrect: true },
        { answerText: 'Penetration test', isCorrect: false },
        { answerText: 'Geographic dispersion', isCorrect: false },
        { answerText: 'Incident response', isCorrect: false },
      ],
    explanation: 'The correct answer is A. Tabletop exercise. A tabletop exercise is a discussion-based session where stakeholders meet to discuss their roles and responsibilities in the event of a security breach or other emergency scenarios. This type of exercise helps organizations prepare for potential incidents by simulating real-world situations and evaluating their response plans.'
  },
    {
      questionText: 'Which of the following is an example of a data protection strategy that uses tokenization?',
      answerOptions: [
        { answerText: 'Encrypting databases containing sensitive data', isCorrect: false },
        { answerText: 'Replacing sensitive data with surrogate values', isCorrect: true },
        { answerText: 'Removing sensitive data from production systems', isCorrect: false },
        { answerText: 'Hashing sensitive data in critical systems', isCorrect: false },
      ],
    explanation: 'Tokenization is a data protection strategy that involves replacing sensitive data with a non-sensitive placeholder, called a token. These tokens are surrogate values that have no meaningful relationship with the original sensitive data, but can still be used in a system without exposing the actual sensitive information. The original data is stored securely in a separate, protected location (often a token vault), and the tokens are used in its place in the production systems. For example, instead of storing a real credit card number, a system might store a token like "12345678", and the real credit card number would only be accessible in the secure token vault.'
  },
    {
      questionText: 'Which of the following is a type of vulnerability that refers to the unauthorized installation of applications on a device through means other than the official application store?',
      answerOptions: [
        { answerText: 'Cross-site scripting', isCorrect: false },
        { answerText: 'Buffer overflow', isCorrect: false },
        { answerText: 'Jailbreaking', isCorrect: false },
        { answerText: 'Side loading', isCorrect: true },
      ],
    explanation: 'Side loading is the process of installing apps from another source rather than the official App Store.'
  },
    {
      questionText: 'Which of the following types of identification methods can be performed on a deployed application during runtime?',
      answerOptions: [
        { answerText: 'Dynamic analysis', isCorrect: true },
        { answerText: 'Code review', isCorrect: false },
        { answerText: 'Package monitoring', isCorrect: false },
        { answerText: 'Bug bounty', isCorrect: false },
      ],
    explanation: 'Dynamic analysis is a method of evaluating a system by observing its behavior as it runs. It can be used to analyze software, structures, or data.'
  },
    {
      questionText: 'Which of the following cryptographic solutions is used to hide the fact that communication is occurring?',
      answerOptions: [
        { answerText: 'Steganography', isCorrect: true },
        { answerText: 'Data masking', isCorrect: false },
        { answerText: 'Tokenization', isCorrect: false },
        { answerText: 'Private key', isCorrect: false },
      ],
    explanation: 'The words communicating occur refer to the image having a hidden message, and this message will be transferred by image from one system to another system.'
  },
    {
      questionText: 'Which of the following steps should be taken before mitigating a vulnerability in a production server?',
      answerOptions: [
        { answerText: 'Escalate the issue to the SDLC team.', isCorrect: false },
        { answerText: 'Use the IR plan to evaluate the changes.', isCorrect: false },
        { answerText: 'Perform a risk assessment to classify the vulnerability.', isCorrect: false },
        { answerText: 'Refer to the change management policy.', isCorrect: true },
      ],
    explanation: 'The correct answer is C. Perform a risk assessment to classify the vulnerability. Before mitigating a vulnerability in a production server, it\'s crucial to perform a risk assessment to understand the potential impact and severity of the vulnerability. This helps in prioritizing the mitigation efforts and ensuring that the most critical vulnerabilities are addressed first.'
  },
    {
      questionText: 'A security engineer needs to quickly identify a signature from a known malicious file. Which of the following analysis methods would the security engineer most likely use?',
      answerOptions: [
        { answerText: 'Static', isCorrect: true },
        { answerText: 'Sandbox', isCorrect: false },
        { answerText: 'Network traffic', isCorrect: false },
        { answerText: 'Package monitoring', isCorrect: false },
      ],
    explanation: 'A. Static analysis Static analysis involves examining the file without executing it. This method is ideal for identifying known signatures, as it allows the security engineer to inspect the file\'s contents (such as its code, headers, or embedded metadata) for recognizable patterns or hash values that match known malicious signatures. Static analysis is quick because it doesn’t require running the file, and it can be done using antivirus software or specialized tools that compare file contents with a database of known threats. Why the other options are less appropriate: C. Network traffic analysis: Network traffic analysis focuses on monitoring network communication for suspicious activity. It is not suitable for identifying file signatures, as it deals with the behavior of files over the network rather than examining the file itself.'
  },
    {
      questionText: 'Which of the following should a company use to provide proof of external network security testing?',
      answerOptions: [
        { answerText: 'Business impact analysis', isCorrect: false },
        { answerText: 'Supply chain analysis', isCorrect: false },
        { answerText: 'Vulnerability assessment', isCorrect: false },
        { answerText: 'Third-party attestation', isCorrect: true },
      ],
    explanation: 'Supply Chain Analysis is usually created by internal staff. A third party creating a supply chain analysis is not common. So, the answer is D Third-party Attestation'
  },
    {
      questionText: 'A security administrator is addressing an issue with a legacy system that communicates data using an unencrypted protocol to transfer sensitive data to a third party. No software updates that use an encrypted protocol are available, so a compensating control is needed. Which of the following are the most appropriate for the administrator to suggest? (Choose two.)',
      answerOptions: [
        { answerText: 'Tokenization', isCorrect: false },
        { answerText: 'Cryptographic downgrade', isCorrect: false },
        { answerText: 'SSH tunneling', isCorrect: true },
        { answerText: 'Segmentation', isCorrect: true },
        { answerText: 'Patch installation', isCorrect: false },
        { answerText: 'Data masking', isCorrect: false },
      ],
    explanation: 'C. SSH tunneling protects data in transit A. Tokenization replaces sensitive data which protects the data a rest I see many answers suggesting segmentation. The question states we are transferring data to a third party, which implies over the internet. You can\'t segment the internet and we have already mitigated the transfer by tunneling over SSH.'
  },
    {
      questionText: 'Which of the following steps in the risk management process involves establishing the scope and potential risks involved with a project?',
      answerOptions: [
        { answerText: 'Risk assessment', isCorrect: false },
        { answerText: 'Risk identification', isCorrect: true },
        { answerText: 'Risk treatment', isCorrect: false },
        { answerText: 'Risk monitoring and review', isCorrect: false },
      ],
    explanation: 'While both are part of risk management, "risk identification" is the initial step of recognizing and listing potential risks, while "risk assessment" involves analyzing and evaluating those identified risks to determine their likelihood and potential impact, essentially prioritizing them for mitigation strategies; in simpler terms, risk identification is just listing possible threats, while risk assessment is figuring out how serious each threat could be'
  },
    {
      questionText: "A company's website is www.company.com. Attackers purchased the domain www.c0mpany.com. Which of the following types of attacks describes this example?",
      answerOptions: [
        { answerText: 'Typosquatting', isCorrect: true },
        { answerText: 'Brand impersonation', isCorrect: false },
        { answerText: 'On-path', isCorrect: false },
        { answerText: 'Watering-hole', isCorrect: false },
      ],
    explanation: 'Typosquatting is a cybercrime that involves registering a domain with a common misspelling of a popular website or brand:'
  },
    {
      questionText: 'Which of the following allows a systems administrator to tune permissions for a file?',
      answerOptions: [
        { answerText: 'Patching', isCorrect: false },
        { answerText: 'Access control list', isCorrect: true },
        { answerText: 'Configuration enforcement', isCorrect: false },
        { answerText: 'Least privilege', isCorrect: false },
      ],
    explanation: 'Tuning permissions for a file refers to adjusting the access controls or permissions settings to ensure that only authorized users or processes can read, write, or execute the file.'
  },
    {
      questionText: 'Which of the following would be the greatest concern for a company that is aware of the consequences of non-compliance with government regulations?',
      answerOptions: [
        { answerText: 'Right to be forgotten', isCorrect: false },
        { answerText: 'Sanctions', isCorrect: true },
        { answerText: 'External compliance reporting', isCorrect: false },
        { answerText: 'Attestation', isCorrect: false },
      ],
    explanation: 'B. Sanctions Reasoning: Sanctions can result in severe financial penalties, legal actions, operational restrictions, or even a ban on conducting business in certain regions. Non-compliance with government regulations (e.g., GDPR, HIPAA, SOX) often leads to heavy fines, lawsuits, and reputational damage. In extreme cases, regulatory sanctions can result in license revocations, asset freezes, or criminal charges against executives. Why Not the Others? A. Right to be Forgotten – This is an aspect of privacy laws like GDPR, but failure to comply might result in fines, whereas sanctions can be more devastating. C. External Compliance Reporting – While important, it is more of a procedural obligation than a direct punitive risk. D. Attestation – This refers to providing formal verification of compliance, but failing to attest isn’t as critical as actual sanctions imposed for violations.'
  },
    {
      questionText: 'Which of the following security concepts is accomplished when granting access after an individual has logged into a computer network?',
      answerOptions: [
        { answerText: 'Authorization', isCorrect: true },
        { answerText: 'Identification', isCorrect: false },
        { answerText: 'Non-repudiation', isCorrect: false },
        { answerText: 'Authentication', isCorrect: false },
      ],
    explanation: 'Authentication before Authorization. By successfully logging in, you have already authenticated. Authorization will then determine what you have access to.'
  },
    {
      questionText: 'A growing organization, which hosts an externally accessible application, adds multiple virtual servers to improve application performance and decrease the resource usage on individual servers. Which of the following solutions is the organization most likely to employ to further increase performance and availability?',
      answerOptions: [
        { answerText: 'Load balancer', isCorrect: true },
        { answerText: 'Jump server', isCorrect: false },
        { answerText: 'Proxy server', isCorrect: false },
        { answerText: 'SD-WAN', isCorrect: false },
      ],
    explanation: 'A. Load balancer Explanation: A load balancer distributes incoming network traffic across multiple servers to: ✔ Improve performance by preventing any single server from being overloaded ✔ Increase availability by ensuring traffic is redirected if a server fails ✔ Enhance scalability by allowing the addition of more servers as needed'
  },
    {
      questionText: 'A systems administrator is concerned users are accessing emails through a duplicate site that is not run by the company. Which of the following is used in this scenario?',
      answerOptions: [
        { answerText: 'Impersonation', isCorrect: false },
        { answerText: 'Replication', isCorrect: false },
        { answerText: 'Phishing', isCorrect: true },
        { answerText: 'Smishing', isCorrect: false },
      ],
    explanation: 'The correct answer is C. Phishing. Phishing involves creating a fake website or email that mimics a legitimate one to trick users into providing sensitive information, such as login credentials. In this scenario, users are accessing emails through a duplicate site that is not run by the company, which is a classic example of phishing.'
  },
    {
      questionText: 'A security engineer at a large company needs to enhance IAM in order to ensure that employees can only access corporate systems during their shifts. Which of the following access controls should the security engineer implement?',
      answerOptions: [
        { answerText: 'Role-based', isCorrect: false },
        { answerText: 'Time-of-day restrictions', isCorrect: true },
        { answerText: 'Least privilege', isCorrect: false },
        { answerText: 'Biometric authentication', isCorrect: false },
      ],
    explanation: 'IAM (Identity and Access Management) setup based on the questions is Time-based Access Management, which is another words Time-of-day restrictions.'
  },
    {
      questionText: 'A company wants to ensure employees are allowed to copy files from a virtual desktop during the workday but are restricted during non-working hours. Which of the following security measures should the company set up?',
      answerOptions: [
        { answerText: 'Digital rights management', isCorrect: false },
        { answerText: 'Role-based access control', isCorrect: false },
        { answerText: 'Time-based access control', isCorrect: true },
        { answerText: 'Network access control', isCorrect: false },
      ],
    explanation: 'C. Time-based access control Explanation: • Time-based access control: Restricts or permits access to resources based on specific time frames. This fits the scenario where file copying is allowed only during working hours.'
  },
    {
      questionText: 'Employees sign an agreement that restricts specific activities when leaving the company. Violating the agreement can result in legal consequences. Which of the following agreements does this best describe?',
      answerOptions: [
        { answerText: 'SLA', isCorrect: false },
        { answerText: 'BPA', isCorrect: false },
        { answerText: 'NDA', isCorrect: true },
        { answerText: 'MOA', isCorrect: false },
      ],
    explanation: 'A non-disclosure agreement (NDA) is a legal contract that limits how confidential information can be used and shared. NDAs are also known as confidentiality agreements, proprietary information agreements, or secrecy agreements.'
  },
    {
      questionText: 'A systems administrator just purchased multiple network devices. Which of the following should the systems administrator perform to prevent attackers from accessing the devices by using publicly available information?',
      answerOptions: [
        { answerText: 'Install endpoint protection.', isCorrect: false },
        { answerText: 'Disable ports/protocols.', isCorrect: false },
        { answerText: 'Change default passwords.', isCorrect: true },
        { answerText: 'Remove unnecessary software.', isCorrect: false },
      ],
    explanation: 'Install endpoint protection is typically used on network devices, but not computers/services. and computer does not have default pw. But network devices like routers, switches, etc. have access by default.'
  },
    {
      questionText: 'A CVE in a key back-end component of an application has been disclosed. The systems administrator is identifying all of the systems in the environment that are susceptible to this risk. Which of the following should the systems administrator perform?',
      answerOptions: [
        { answerText: 'Packet capture', isCorrect: false },
        { answerText: 'Vulnerability scan', isCorrect: true },
        { answerText: 'Metadata analysis', isCorrect: false },
        { answerText: 'Automated reporting', isCorrect: false },
      ],
    explanation: 'B. Vulnerability Scan Why? A vulnerability scan systematically checks systems against a database of known vulnerabilities (including CVEs). It helps identify which systems, applications, or services are affected by the disclosed CVE. Most vulnerability scanning tools (e.g., Nessus, Qualys, OpenVAS) provide detailed reports and potential remediation steps. Why Not the Others? A. Packet Capture – Used for network traffic analysis, but it won’t directly identify vulnerable systems. C. Metadata Analysis – Involves examining file or system metadata, which is not relevant for detecting software vulnerabilities. D. Automated Reporting – Helps document findings but does not actively identify vulnerable systems.'
  },
    {
      questionText: 'Which of the following activities uses OSINT?',
      answerOptions: [
        { answerText: 'Social engineering testing', isCorrect: true },
        { answerText: 'Data analysis of logs', isCorrect: false },
        { answerText: 'Collecting evidence of malicious activity', isCorrect: false },
        { answerText: 'Producing IOC for malicious artifacts', isCorrect: false },
      ],
    explanation: 'Besides threat feeds, OSINT is often used to create cybersecurity threat maps that illustrate cyber threats overlaid on a diagrammatic representation of a geographical area. Figure 12-2 illustrates a threat map. Threat maps help in visualizing attacks and provide a limited amount of context on the source and the target countries, the attack types, and historical and near real-time data about threats.'
  },
    {
      questionText: 'Which of the following are the best security controls for controlling on-premises access? (Choose two.)',
      answerOptions: [
        { answerText: 'Swipe card', isCorrect: true },
        { answerText: 'Picture ID', isCorrect: false },
        { answerText: 'Phone authentication application', isCorrect: false },
        { answerText: 'Biometric scanner', isCorrect: true },
        { answerText: 'Camera', isCorrect: false },
        { answerText: 'Memorable question', isCorrect: false },
      ],
    explanation: 'A. Swipe Card ✔ Provides physical access control to restricted areas. ✔ Can be integrated with access logs to track entries and exits. ✔ Easy to revoke or deactivate if lost or stolen. D. Biometric Scanner ✔ Verifies identity using unique physical traits (e.g., fingerprint, iris, or facial recognition). ✔ Cannot be shared or stolen like swipe cards or PIN codes. ✔ Adds an extra layer of security by ensuring the person entering is the authorized individual.'
  },
    {
      questionText: 'A company is considering an expansion of access controls for an application that contractors and internal employees use to reduce costs. Which of the following risk elements should the implementation team understand before granting access to the application?',
      answerOptions: [
        { answerText: 'Threshold', isCorrect: false },
        { answerText: 'Appetite', isCorrect: true },
        { answerText: 'Avoidance', isCorrect: false },
        { answerText: 'Register', isCorrect: false },
      ],
    explanation: 'Risk appetite is the amount and type of risk that an organization is willing to accept in pursuit of its objectives. Risk appetile is a kind of risk that a company can tolerate.'
  },
    {
      questionText: 'Which of the following is the act of proving to a customer that software developers are trained on secure coding?',
      answerOptions: [
        { answerText: 'Assurance', isCorrect: false },
        { answerText: 'Contract', isCorrect: false },
        { answerText: 'Due diligence', isCorrect: false },
        { answerText: 'Attestation', isCorrect: true },
      ],
    explanation: 'Due diligence refers to the comprehensive process of evaluating and mitigating risks before making a decision or entering into an agreement. So only attestation is the only reasonable answer.'
  },
    {
      questionText: 'An administrator is creating a secure method for a contractor to access a test environment. Which of the following would provide the contractor with the best access to the test environment?',
      answerOptions: [
        { answerText: 'Application server', isCorrect: false },
        { answerText: 'Jump server', isCorrect: true },
        { answerText: 'RDP server', isCorrect: false },
        { answerText: 'Proxy server', isCorrect: false },
      ],
    explanation: 'A jump server is a secure intermediate server designed to manage and control access to other servers or environments. Contractors or external users can connect to the jump server, which then provides them limited, controlled access to the target environment. The jump server acts as a gatekeeper, isolating the test environment from direct external access. This reduces the attack surface and ensures that access is limited and monitored.'
  },
    {
      questionText: 'A security analyst notices unusual behavior on the network. The IDS on the network was not able to detect the activities. Which of the following should the security analyst use to help the IDS detect such attacks in the future?',
      answerOptions: [
        { answerText: 'Signatures', isCorrect: true },
        { answerText: 'Trends', isCorrect: false },
        { answerText: 'Honeypot', isCorrect: false },
        { answerText: 'Reputation', isCorrect: false },
    ],
    explanation: 'The correct answer is A. Signatures. Signatures are patterns or known characteristics of malicious activity that an Intrusion Detection System (IDS) uses to identify threats. If the IDS failed to detect unusual behavior, updating or adding new signatures would help it recognize such attacks in the future.'
  },
    {
      questionText: 'To which of the following security categories does an EDR solution belong?',
      answerOptions: [
      { answerText: 'Physical', isCorrect: false },
      { answerText: 'Operational', isCorrect: false },
      { answerText: 'Managerial', isCorrect: false },
      { answerText: 'Technical', isCorrect: true },
    ],
    explanation: 'The correct answer is D. Technical. An Endpoint Detection and Response (EDR) solution belongs to the technical security category, as it involves the use of technology to detect, monitor, and respond to security threats on endpoints (e.g., computers, mobile devices).'
  },
  {
    questionText: 'A company relies on open-source software libraries to build the software used by its customers. Which of the following vulnerability types would be the most difficult to remediate due to the company’s reliance on open-source libraries?',
    answerOptions: [
      { answerText: 'Buffer overflow', isCorrect: false },
      { answerText: 'SQL injection', isCorrect: false },
      { answerText: 'Cross-site scripting', isCorrect: false },
      { answerText: 'Zero-day', isCorrect: true },
    ],
    explanation: 'The correct answer is: D. Zero-day Explanation: Zero-day vulnerabilities are the most difficult to remediate because they are unknown to the software vendor or the open-source community at the time of exploitation. Since the company relies on open-source libraries, it may not have control over the discovery or patching of such vulnerabilities. Remediation often depends on the open-source community or third-party maintainers to identify and fix the issue, which can take time. Buffer overflow (A), SQL injection (B), and Cross-site scripting (C) are well-known vulnerability types with established remediation practices. These can typically be addressed through code reviews, secure coding practices, and applying patches or updates provided by the open-source community. Thus, zero-day vulnerabilities pose the greatest challenge due to their unpredictable nature and reliance on external parties for fixes.'
  },
  {
    questionText: 'An organization has a new regulatory requirement to implement corrective controls on a financial system. Which of the following is the most likely reason for the new requirement?',
    answerOptions: [
      { answerText: 'To defend against insider threats altering banking details', isCorrect: false },
      { answerText: 'To ensure that errors are not passed to other systems', isCorrect: true },
      { answerText: 'To allow for business insurance to be purchased', isCorrect: false },
      { answerText: 'To prevent unauthorized changes to financial data', isCorrect: false },
    ],
    explanation: 'B. To ensure that errors are not passed to other systems Explanation: ✔ Corrective controls are designed to identify and fix issues after they occur, ensuring that errors do not propagate to other systems. ✔ In a financial system, errors can lead to incorrect transactions, misstatements, or compliance violations. ✔ Regulatory requirements often mandate corrective controls to detect, log, and rectify mistakes before they cause widespread issues. Why not the other options? A. To defend against insider threats altering banking details – This relates more to preventive and detective controls rather than corrective controls. C. To allow for business insurance to be purchased – Compliance may influence insurance policies, but corrective controls are primarily implemented for operational and regulatory integrity. D. To prevent unauthorized changes to financial data – Preventing changes is a preventive control, whereas corrective controls focus on identifying and fixing errors post-occurrence.'
  },
  {
    questionText: 'Which of the following is the stage in an investigation when forensic images are obtained?',
    answerOptions: [
      { answerText: 'Acquisition', isCorrect: true },
      { answerText: 'Preservation', isCorrect: false },
      { answerText: 'Reporting', isCorrect: false },
      { answerText: 'E-discovery', isCorrect: false },
    ],
    explanation: ''
  },
  {
    questionText: 'Which of the following describes the difference between encryption and hashing?',
    answerOptions: [
      { answerText: 'Encryption protects data in transit, while hashing protects data at rest.', isCorrect: false },
      { answerText: 'Encryption replaces cleartext with ciphertext, while hashing calculates a checksum.', isCorrect: true },
      { answerText: 'Encryption ensures data integrity, while hashing ensures data confidentiality.', isCorrect: false },
      { answerText: 'Encryption uses a public-key exchange, while hashing uses a private key.', isCorrect: false },
    ],
    explanation: '. Encryption replaces cleartext with ciphertext, while hashing calculates a checksum. Explanation: ✔ Encryption converts plaintext into ciphertext using an algorithm and a key, allowing data to be decrypted when needed. ✔ Hashing generates a fixed-length checksum (hash) from input data, ensuring data integrity but not reversibility (i.e., hashes cannot be decrypted). Why not the other options? A. Encryption protects data in transit, while hashing protects data at rest. ❌ Incorrect – Encryption protects both data in transit and at rest, while hashing is used for data integrity verification, not storage security. C. Encryption ensures data integrity, while hashing ensures data confidentiality. ❌ Incorrect – Encryption ensures confidentiality, and hashing ensures integrity, not the other way around. D. Encryption uses a public-key exchange, while hashing uses a private key. ❌ Incorrect – Hashing does not use any keys. Public-key exchange applies only to asymmetric encryption, not encryption as a whole.'
  },
  {
    questionText: 'A Chief Information Security Officer (CISO) has developed information security policies that relate to the software development methodology. Which of the following would the CISO most likely include in the organization’s documentation?',
    answerOptions: [
      { answerText: 'Peer review requirements', isCorrect: true },
      { answerText: 'Multifactor authentication', isCorrect: false },
      { answerText: 'Branch protection tests', isCorrect: false },
      { answerText: 'Secrets management configurations', isCorrect: false },
    ],
    explanation: 'The correct answer is: A. Peer review requirements Explanation: Peer review requirements are directly related to software development methodologies and are a critical part of ensuring code quality, security, and adherence to best practices. Including peer review requirements in the organization’s documentation aligns with the CISO’s focus on integrating security into the software development lifecycle (SDLC). Multifactor authentication (B) is a security control but is more related to access management than software development methodologies. Branch protection tests (C) are specific to version control systems (e.g., Git) and are more operational in nature rather than a policy-level requirement. Secrets management configurations (D) are important for securing sensitive information like API keys and passwords, but they are more of an implementation detail rather than a policy-level documentation item.'
  },
  {
    questionText: 'An organization is developing a security program that conveys the responsibilities associated with the general operation of systems and software within the organization. Which of the following documents would most likely communicate these expectations?',
    answerOptions: [
      { answerText: 'Business continuity plan', isCorrect: false },
      { answerText: 'Change management procedure', isCorrect: false },
      { answerText: 'Acceptable use policy', isCorrect: true },
      { answerText: 'Software development life cycle policy', isCorrect: false },
    ],
    explanation: 'C. Acceptable Use Policy (AUP) Explanation: ✔ An Acceptable Use Policy (AUP) defines the responsibilities and expectations for employees regarding the proper operation and security of systems, software, and data. ✔ It establishes guidelines for what is and isn’t allowed when using company resources. ✔ Typically includes policies on access control, data protection, and security best practices. Why not the other options? A. Business Continuity Plan (BCP) – Focuses on ensuring operations continue during disruptions, not on daily system responsibilities. B. Change Management Procedure – Covers how changes to IT systems are handled, but not general operational responsibilities. D. Software Development Life Cycle (SDLC) Policy – Guides software development practices, not the broader operational use of systems.'
  },
  {
    questionText: 'A security analyst created a fake account and saved the password in a non-readily accessible directory in a spreadsheet. An alert was also configured to notify the security team if the spreadsheet is opened. Which of the following best describes the deception method being deployed?',
    answerOptions: [
      { answerText: 'Honeypot', isCorrect: false },
      { answerText: 'Honeyfile', isCorrect: true },
      { answerText: 'Honeytoken', isCorrect: false },
      { answerText: 'Honeynet', isCorrect: false },
    ],
    explanation: 'GPT: The correct answer is: ✅ B. Honeyfile Explanation: A honeyfile is a decoy file that appears valuable (e.g., contains credentials, financial data, or sensitive information). It is placed in a monitored location to detect unauthorized access. In this case: The analyst saved a fake account and password in a spreadsheet. The spreadsheet is stored in a non-obvious directory. An alert triggers when it\'s opened. These are textbook characteristics of a honeyfile. ❌ Why the other options are incorrect: Option Why it\'s not correct A. Honeypot A decoy system or server, not a file. C. Honeytoken A piece of fake data (e.g., fake credential or ID) — similar, but not specifically a file-based trap. D. Honeynet A network of honeypots, much broader in scope.'
  },
  {
    questionText: 'Which of the following is the best way to provide secure, remote access for employees while minimizing the exposure of a company’s internal network?',
    answerOptions: [
      { answerText: 'VPN', isCorrect: true },
      { answerText: 'LDAP', isCorrect: false },
      { answerText: 'FTP', isCorrect: false },
      { answerText: 'RADIUS', isCorrect: false },
    ],
    explanation: 'A. VPN (Virtual Private Network) Explanation: ✔ Encrypts remote connections, preventing eavesdropping and unauthorized access. ✔ Minimizes exposure by only allowing authenticated users into the network. ✔ Can be configured with multi-factor authentication (MFA) for added security. ✔ Supports split tunneling to limit internal network exposure while allowing necessary access. Why not the other options? B. LDAP (Lightweight Directory Access Protocol) – Used for authentication but not for secure remote access. C. FTP (File Transfer Protocol) – Used for file transfers; not a secure remote access solution. D. RADIUS (Remote Authentication Dial-In User Service) – Provides authentication and authorization but requires a VPN or another access method for secure remote connectivity.'
  },
  {
    questionText: 'A company wants to track modifications to the code that is used to build new virtual servers. Which of the following will the company most likely deploy?',
    answerOptions: [
      { answerText: 'Change management ticketing system', isCorrect: false },
      { answerText: 'Behavioral analyzer', isCorrect: false },
      { answerText: 'Collaboration platform', isCorrect: false },
      { answerText: 'Version control tool', isCorrect: true },
    ],
    explanation: 'This don\'t even feel like a Sec+ question'
  },
  {
    questionText: 'Which of the following documents details how to accomplish a technical security task?',
    answerOptions: [
      { answerText: 'Standard', isCorrect: false },
      { answerText: 'Policy', isCorrect: false },
      { answerText: 'Guideline', isCorrect: false },
      { answerText: 'Procedure', isCorrect: true },
    ],
    explanation: 'D. Procedure Explanation: ✔ A procedure outlines the step-by-step instructions to perform a specific technical task. It provides detailed actions to achieve a particular security objective. ✔ Procedures are actionable and provide specific methods to follow, often used in hands-on implementation of security measures. Why not the other options? A. Standard – Defines required security controls or configurations but does not provide the steps for implementation. B. Policy – Sets the high-level principles or rules of security but does not explain how to carry out tasks. C. Guideline – Offers recommended best practices but is not prescriptive in terms of specific actions.'
  },
  {
    questionText: 'While conducting a business continuity tabletop exercise, the security team becomes concerned by potential impact if a generator was to develop a fault during failover. Which of the following is the team most likely to consider in regard to risk management activities?',
    answerOptions: [
      { answerText: 'RPO', isCorrect: false },
      { answerText: 'ARO', isCorrect: false },
      { answerText: 'BIA', isCorrect: true },
      { answerText: 'MTTR', isCorrect: false },
    ],
    explanation: 'most times, check for the basic word used in the question, it highlights \'impact", so the answer should be BIA (Business impact analysis)'
  },
  {
    questionText: 'Which of the following is prevented by proper data sanitization?',
    answerOptions: [
      { answerText: 'Hackers’ ability to obtain data from used hard drives', isCorrect: true },
      { answerText: 'Devices reaching end-of-life and losing support', isCorrect: false },
      { answerText: 'Disclosure of sensitive data through incorrect classification', isCorrect: false },
      { answerText: 'Incorrect inventory data leading to a laptop shortage', isCorrect: false },
    ],
    explanation: 'https://www.google.com/search?q=prevented+by+proper+data+sanitization%3F&rlz=1C1GCEA_enUS1070US1072&oq=prevented+by+proper+data+sanitization%3F&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIICAEQABgWGB4yDQgCEAAYhgMYgAQYigUyCggDEAAYgAQYogQyBwgEEAAY7wUyCggFEAAYogQYiQUyCggGEAAYgAQYogQyCggHEAAYgAQYogTSAQk0NDc0ajBqMTWoAgCwAgA&sourceid=chrome&ie=UTF-8'
  },
  {
    questionText: 'A certificate authority needs to post information about expired certificates. Which of the following would accomplish this task?',
    answerOptions: [
      { answerText: 'TPM', isCorrect: false },
      { answerText: 'CRL', isCorrect: true },
      { answerText: 'PKI', isCorrect: false },
      { answerText: 'CSR', isCorrect: false },
    ],
    explanation: 'The correct answer is: B. CRL (Certificate Revocation List) Explanation: CRL (Certificate Revocation List) is a list of digital certificates that have been revoked or expired before their scheduled expiration date. Certificate authorities (CAs) use CRLs to publicly post information about certificates that are no longer valid, ensuring that relying parties can check the status of a certificate. TPM (Trusted Platform Module) (A) is a hardware component used for secure cryptographic operations, not related to posting expired certificate information. PKI (Public Key Infrastructure) (C) is the framework that manages digital certificates and public-key encryption, but it is not a specific mechanism for posting expired certificate information. CSR (Certificate Signing Request) (D) is a request sent to a CA to issue a digital certificate, which is unrelated to posting expired certificate information.'
  },
  {
    questionText: 'Which of the following can best contribute to prioritizing patch applications?',
    answerOptions: [
      { answerText: 'CVSS', isCorrect: true },
      { answerText: 'SCAP', isCorrect: false },
      { answerText: 'OSINT', isCorrect: false },
      { answerText: 'CVE', isCorrect: false },
    ],
    explanation: 'A. CVSS (Common Vulnerability Scoring System) Explanation: ✔ CVSS provides a standardized scoring system to evaluate the severity of vulnerabilities, helping organizations prioritize which patches to apply based on risk and impact. ✔ CVSS scores consider factors like exploitability, impact, and ease of remediation, making it a useful tool for prioritizing patch applications. Why not the other options? B. SCAP (Security Content Automation Protocol) – SCAP is a set of standards for automating vulnerability management, but CVSS is the specific tool for prioritizing based on severity. C. OSINT (Open Source Intelligence) – While OSINT can provide useful information about vulnerabilities and threats, it does not specifically prioritize patches. D. CVE (Common Vulnerabilities and Exposures) – CVEs provide unique identifiers for vulnerabilities, but they don’t include the severity scoring that helps prioritize patching.'
  },
  {
    questionText: 'A systems administrator creates a script that validates OS version, patch levels, and installed applications when users log in. Which of the following examples best describes the purpose of this script?',
    answerOptions: [
      { answerText: 'Resource scaling', isCorrect: false },
      { answerText: 'Policy enumeration', isCorrect: false },
      { answerText: 'Baseline enforcement', isCorrect: true },
      { answerText: 'Guard rails implementation', isCorrect: false },
    ],
    explanation: 'The correct answer is: C. Baseline enforcement Explanation: Baseline enforcement refers to ensuring that systems comply with a predefined set of standards or configurations. In this case, the script validates the OS version, patch levels, and installed applications against a baseline to ensure consistency and security across all systems. Resource scaling (A) involves adjusting system resources (e.g., CPU, memory) based on demand, which is unrelated to the script\'s purpose. Policy enumeration (B) refers to listing or identifying policies, but the script is actively validating and enforcing compliance, not just enumerating policies. Guard rails implementation (D) typically involves setting boundaries or constraints to prevent unintended actions, which is not the primary purpose of this script.'
  },
  {
    questionText: 'A security analyst learns that an attack vector, which was used as a part of a recent incident, was a well-known IoT device exploit. The analyst needs to review logs to identify the time of initial exploit. Which of the following logs should the analyst review first?',
    answerOptions: [
      { answerText: 'Endpoint', isCorrect: false },
      { answerText: 'Application', isCorrect: false },
      { answerText: 'Firewall', isCorrect: true },
      { answerText: 'NAC', isCorrect: false },
    ],
    explanation: 'The correct answer is: C. Firewall Explanation: Firewall logs are the most likely to provide information about the initial exploit, as firewalls monitor and log network traffic, including attempts to exploit vulnerabilities in IoT devices. These logs can show suspicious or unauthorized connections to the IoT device, which can help identify the time of the initial exploit. Endpoint logs (A) might provide details about the affected device, but they are less likely to capture the initial network-based exploit. Application logs (B) are specific to applications and may not be relevant if the exploit targeted the IoT device itself rather than an application running on it. NAC (Network Access Control) logs (D) focus on device authentication and network access, which may not directly reveal the time of the exploit. Thus, Firewall logs are the most appropriate starting point for identifying the time of the initial exploit.'
  },
  {
    questionText: 'A company’s gate access logs show multiple entries from an employee’s ID badge within a two-minute period. Which of the following is this an example of?',
    answerOptions: [
      { answerText: 'RFID cloning', isCorrect: true },
      { answerText: 'Side-channel attack', isCorrect: false },
      { answerText: 'Shoulder surfing', isCorrect: false },
      { answerText: 'Tailgating', isCorrect: false },
    ],
    explanation: 'D. Tailgating: This refers to an unauthorized person physically following an authorized person through a secured entry point without using their own credentials. It would not produce multiple log entries from the same badge'
  },
  {
    questionText: 'Which of the following most accurately describes the order in which a security engineer should implement secure baselines?',
    answerOptions: [
      { answerText: 'Deploy, maintain, establish', isCorrect: false },
      { answerText: 'Establish, maintain, deploy', isCorrect: false },
      { answerText: 'Establish, deploy, maintain', isCorrect: true },
      { answerText: 'Deploy, establish, maintain', isCorrect: false },
    ],
    explanation: 'C. Establish, Deploy, Maintain Establish – First, the security engineer must define the secure baseline based on best practices, compliance requirements, and organizational needs. This includes: Configuring secure settings for operating systems, applications, and network devices. Following industry standards (e.g., CIS benchmarks, NIST, ISO 27001). Deploy – Once the baseline is established, it must be implemented across all systems. This includes: Applying configurations to production environments. Ensuring proper enforcement through automation (e.g., Group Policies, Ansible, SCCM). Maintain – Security is an ongoing process, so baselines must be regularly updated and monitored to address new threats. This includes: Patching vulnerabilities. Conducting compliance audits. Adjusting configurations based on evolving threats.'
  },
  {
    questionText: 'A SOC analyst establishes a remote control session on an end user’s machine and discovers the following in a file: gmail.com[ENT][email protected][ENT]NoOneCanGuessThis123![ENT]Hello Susan, it was great to see you the other day! Let’s plan a followup[BACKSPACE]follow-up meeting soon. Here is the link to register. [RTN][CTRL]c [CTRL]v [RTN]after[BACKSPACE]After you register give me a call on my cellphone. Which of the following actions should the SOC analyst perform first?',
    answerOptions: [
      { answerText: 'Advise the user to change passwords.', isCorrect: true },
      { answerText: 'Reimage the end user’s machine.', isCorrect: false },
      { answerText: 'Check the policy on personal email at work.', isCorrect: false },
      { answerText: 'Check host firewall logs.', isCorrect: false },
    ],
    explanation: ''
  },
  {
    questionText: 'Environmental variables are a concern when reviewing potential system vulnerabilities. Which of the following is the primary reason for this concern?',
    answerOptions: [
      { answerText: 'The contents of environmental variables could affect the scope and impact of an exploited vulnerability.', isCorrect: true },
      { answerText: 'In-memory environmental variable values can be overwritten and used by attackers to insert malicious code.', isCorrect: false },
      { answerText: 'Environmental variables define cryptographic standards for the system and could create vulnerabilities if deprecated algorithms are used.', isCorrect: false },
      { answerText: 'Environmental variables will determine when updates are run and could mitigate the likelihood of vulnerability exploitation.', isCorrect: false },
    ],
    explanation: ''
  },
  {
    questionText: 'A company evaluates several options that would allow employees to have remote access to the network. The security team wants to ensure the solution includes AAA to comply with internal security policies. Which of the following should the security team recommend?',
    answerOptions: [
      { answerText: 'IPSec with RADIUS', isCorrect: true },
      { answerText: 'RDP connection with LDAPS', isCorrect: false },
      { answerText: 'Web proxy for all remote traffic', isCorrect: false },
      { answerText: 'Jump server with 802.1X', isCorrect: false },
    ],
    explanation: 'The correct answer is: A. IPSec with RADIUS Explanation: IPSec with RADIUS provides a secure remote access solution that includes AAA (Authentication, Authorization, and Accounting) capabilities. RADIUS (Remote Authentication Dial-In User Service) is a protocol specifically designed for AAA, ensuring that users are authenticated, authorized, and their activities are logged. IPSec (Internet Protocol Security) adds encryption to secure the data transmitted over the connection. RDP connection with LDAPS (B) provides secure remote desktop access but does not inherently include AAA functionality. Web proxy for all remote traffic (C) is not a remote access solution and does not provide AAA capabilities. Jump server with 802.1X (D) is used for secure access to internal resources but does not inherently provide AAA for remote access. 802.1X is primarily used for network access control.'
  },
  {
    questionText: 'An administrator must replace an expired SSL certificate. Which of the following does the administrator need to create the new SSL certificate?',
    answerOptions: [
      { answerText: 'CSR', isCorrect: true },
      { answerText: 'OCSP', isCorrect: false },
      { answerText: 'Key', isCorrect: false },
      { answerText: 'CRL', isCorrect: false },
    ],
    explanation: 'The correct answer is A. CSR (Certificate Signing Request). To replace an expired SSL certificate, the administrator needs to generate a new SSL certificate, which involves creating a CSR. The CSR is a request sent to a Certificate Authority (CA) that includes information about the server and organization. The CA uses this information to create and sign a new SSL certificate.'
  },
  {
    questionText: 'A systems administrator receives a text message from an unknown number claiming to be the Chief Executive Officer of the company. The message states an emergency situation requires a password reset. Which of the following threat vectors is being used?',
    answerOptions: [
      { answerText: 'Typosquatting', isCorrect: false },
      { answerText: 'Smishing', isCorrect: true },
      { answerText: 'Pretexting', isCorrect: false },
      { answerText: 'Impersonation', isCorrect: false },
    ],
    explanation: 'B. Smishing Why? Smishing (SMS Phishing) is a type of social engineering attack where an attacker sends fraudulent text messages (SMS) to trick the recipient into taking action, such as resetting a password or providing sensitive information. In this case, the attacker pretends to be the CEO and tries to manipulate the systems administrator into resetting a password, which could lead to unauthorized access. Why Not the Others? A. Typosquatting – This involves creating fake websites with misspelled domain names to trick users into visiting them, not SMS-based attacks. C. Pretexting – A broader social engineering technique where the attacker creates a fabricated scenario (pretext) to obtain information, but in this case, the attack method is specifically via SMS, making it smishing. D. Impersonation – While the attacker is pretending to be the CEO, the delivery method (SMS) classifies this as smishing rather than general impersonation.'
  },
  {
    questionText: 'A Chief Information Security Officer (CISO) wants to:\n\n• Prevent employees from downloading malicious content.\n• Establish controls based on departments and users.\n• Map internet access for business applications to specific service accounts.\n• Restrict content based on categorization.\n\nWhich of the following should the CSO implement?',
    answerOptions: [
      { answerText: 'Web application firewall', isCorrect: false },
      { answerText: 'Secure DNS server', isCorrect: false },
      { answerText: 'Jump server', isCorrect: false },
      { answerText: 'Next-generation firewall', isCorrect: true },
    ],
    explanation: ''
  },
  {
    questionText: 'A company is aware of a given security risk related to a specific market segment. The business chooses not to accept responsibility and target their services to a different market segment. Which of the following describes this risk management strategy?',
    answerOptions: [
      { answerText: 'Exemption', isCorrect: false },
      { answerText: 'Exception', isCorrect: false },
      { answerText: 'Avoid', isCorrect: true },
      { answerText: 'Transfer', isCorrect: false },
    ],
    explanation: 'C. Avoid Explanation: ✔ Risk avoidance involves modifying business operations to eliminate the risk rather than mitigating or transferring it. ✔ In this scenario, the company chooses not to accept responsibility and shifts its focus to a different market segment, effectively avoiding the risk altogether. Why not the other options? A. Exemption – Not a recognized risk management strategy in this context. B. Exception – Typically refers to granting temporary permission to bypass a security policy, not changing business strategy. D. Transfer – Would involve shifting the risk to a third party (e.g., buying insurance or outsourcing), which is not what’s happening here.'
  },
  {
    questionText: 'A security analyst needs to improve the company’s authentication policy following a password audit. Which of the following should be included in the policy? (Choose two.)',
    answerOptions: [
      { answerText: 'Length', isCorrect: true },
      { answerText: 'Complexity', isCorrect: true },
      { answerText: 'Least privilege', isCorrect: false },
      { answerText: 'Something you have', isCorrect: false },
      { answerText: 'Security keys', isCorrect: false },
      { answerText: 'Biometrics', isCorrect: false },
    ],
    explanation: 'A.B: Length + Complexity'
  },
  {
    questionText: 'Which of the following is an example of a treatment strategy for a continuous risk?',
    answerOptions: [
      { answerText: 'Email gateway to block phishing attempts', isCorrect: false },
      { answerText: 'Background checks for new employees', isCorrect: false },
      { answerText: 'Dual control requirements for wire transfers', isCorrect: false },
      { answerText: 'Branch protection as part of the CI/CD pipeline', isCorrect: true },
    ],
    explanation: 'Again a poor question by CompTIA. All 4 answers are continuous risks and corresponding treatment strategies. A. E-Mails are always a risk. (Phishing) B. New employees are always a security risk, since you don\'t know them- C. Dual Control is a must in Finance to reduce fraud. D. CI/CD pipeline reduces risks in code. And code is always vulnerable. The only think I can image is, that CompTIA tries to refer to "Integrated Penetration Testing" where they explain this concept related to CI/CD. Sec+ Student Guide . https://informer.io/resources/continuous-penetration-testing Good luck on the exam!'
  },
  {
    questionText: 'An organization wants to deploy software in a container environment to increase security. Which of the following would limit the organization’s ability to achieve this goal?',
    answerOptions: [
      { answerText: 'Regulatory compliance', isCorrect: false },
      { answerText: 'Patch availability', isCorrect: false },
      { answerText: 'Kernel version', isCorrect: false },
      { answerText: 'Monolithic code', isCorrect: true },
    ],
    explanation: ''
  },
  {
    questionText: 'Prior to implementing a design change, the change must go through multiple steps to ensure that it does not cause any security issues. Which of the following is most likely to be one of those steps?',
    answerOptions: [
      { answerText: 'Board review', isCorrect: false },
      { answerText: 'Service restart', isCorrect: false },
      { answerText: 'Backout planning', isCorrect: true },
      { answerText: 'Maintenance', isCorrect: false },
    ],
    explanation: 'Part of the change control process C. Backout planning Explanation: Before implementing a design change, organizations need a backout plan to ensure that if something goes wrong—such as security vulnerabilities, performance issues, or unexpected failures—they can quickly revert to the previous stable state. This minimizes downtime and potential security risks.'
  },
  {
    questionText: 'The internal audit team determines a software application is no longer in scope for external reporting requirements. Which of the following will confirm that the application is no longer applicable?',
    answerOptions: [
      { answerText: 'Data inventory and retention', isCorrect: false },
      { answerText: 'Right to be forgotten', isCorrect: false },
      { answerText: 'Due care and due diligence', isCorrect: false },
      { answerText: 'Acknowledgement and attestation', isCorrect: true },
    ],
    explanation: 'Acknowledgement and attestation is the most appropriate method to formally confirm that a software application is no longer applicable for external reporting requirements. This ensures that there is a documented and verifiable statement from the relevant parties affirming the change in status'
  },
  {
    questionText: 'Which of the following are the first steps an analyst should perform when developing a heat map? (Choose two.)',
    answerOptions: [
      { answerText: 'Methodically walk around the office noting Wi-Fi signal strength.', isCorrect: true },
      { answerText: 'Log in to each access point and check the settings.', isCorrect: false },
      { answerText: 'Create or obtain a layout of the office.', isCorrect: true },
      { answerText: 'Measure cable lengths between access points.', isCorrect: false },
      { answerText: 'Review access logs to determine the most active devices.', isCorrect: false },
      { answerText: 'Remove possible impediments to radio transmissions.', isCorrect: false },
    ],
    explanation: 'I would say B and C. C is obvious, you need a floorplan to build the heat map against. B would be another first step to perform before actually creating the heat map. You should make sure all the APs are properly configured and your frequency layout is optimal before you perform the heat map test. A is the act of actually testing the heat map is is not one of the first steps. It is in fact, one of the final ones.'
  },
  {
    questionText: 'Which of the following is used to improve security and overall functionality without losing critical application data?',
    answerOptions: [
      { answerText: 'Reformatting', isCorrect: false },
      { answerText: 'Decommissioning', isCorrect: false },
      { answerText: 'Patching', isCorrect: true },
      { answerText: 'Encryption', isCorrect: false },
    ],
    explanation: 'Patching'
  },
  {
    questionText: 'An organization is preparing to export proprietary software to a customer. Which of the following would be the best way to prevent the loss of intellectual property?',
    answerOptions: [
      { answerText: 'Code signing', isCorrect: false },
      { answerText: 'Obfuscation', isCorrect: true },
      { answerText: 'Tokenization', isCorrect: false },
      { answerText: 'Blockchain', isCorrect: false },
    ],
    explanation: 'B. Obfuscation Explanation: Obfuscation is the process of modifying code to make it difficult for unauthorized parties to understand, reverse-engineer, or modify while maintaining its functionality. This helps protect proprietary software from intellectual property theft when exporting to external customers. Breakdown of the other options: A. Code signing: Ensures authenticity and integrity but does not prevent reverse engineering or IP theft. C. Tokenization: Replaces sensitive data with tokens for security purposes, but it is primarily used for data protection rather than software IP protection. D. Blockchain: Can provide tamper-proof records but does not directly prevent software reverse engineering or protect proprietary code.'
  },
  {
    questionText: 'After a series of account compromises and credential misuse, a company hires a security manager to develop a security program. Which of the following steps should the security manager take first to increase security awareness?',
    answerOptions: [
      { answerText: 'Evaluate tools that identify risky behavior and distribute reports on the findings.', isCorrect: false },
      { answerText: 'Send quarterly newsletters that explain the importance of password management.', isCorrect: false },
      { answerText: 'Develop phishing campaigns and notify the management team of any successes.', isCorrect: false },
      { answerText: 'Update policies and handbooks to ensure all employees are informed of the new procedures.', isCorrect: true },
    ],
    explanation: 'I go with D'
  },
  {
    questionText: 'Which of the following should be used to ensure a device is inaccessible to a network-connected resource?',
    answerOptions: [
      { answerText: 'Disablement of unused services', isCorrect: false },
      { answerText: 'Web application firewall', isCorrect: false },
      { answerText: 'Host isolation', isCorrect: true },
      { answerText: 'Network-based IDS', isCorrect: false },
    ],
    explanation: 'Host isolation involves separating a device from network access or restricting its ability to communicate with other resources on the network. This ensures that the device is inaccessible to other network-connected resources, preventing potential unauthorized access or communication. Breakdown of the other options: A. Disablement of unused services: Helps improve security by turning off unnecessary services but does not fully isolate a device from the network. B. Web application firewall (WAF): Protects web applications by filtering and monitoring HTTP traffic but does not prevent a device from being accessible to other network resources. D. Network-based IDS (Intrusion Detection System): Monitors network traffic for malicious activity but does not actively isolate a device from the network.'
  },
  {
    questionText: 'In which of the following will unencrypted network traffic most likely be found?',
    answerOptions: [
      { answerText: 'SDN', isCorrect: false },
      { answerText: 'IoT', isCorrect: true },
      { answerText: 'VPN', isCorrect: false },
      { answerText: 'SCADA', isCorrect: false },
    ],
    explanation: 'Unencrypted network traffic is most likely to be found in B. IoT (Internet of Things). Many IoT devices, especially low-cost or low-power ones, often transmit data without encryption, which can make them vulnerable to interception. This is a common security concern in the IoT ecosystem. A. SDN (Software-Defined Networking): Typically uses encrypted communication protocols, especially for control planes. C. VPN (Virtual Private Network): VPNs are designed to encrypt traffic to protect data transmission. D. SCADA (Supervisory Control and Data Acquisition): While SCADA systems are critical and often operate on specialized protocols, modern implementations are increasingly using encryption to secure communications, although older systems may still have vulnerabilities. So, IoT stands out as the most likely for unencrypted traffic.'
  },
  {
    questionText: 'Which of the following is the best reason to perform a tabletop exercise?',
    answerOptions: [
      { answerText: 'To address audit findings', isCorrect: false },
      { answerText: 'To collect remediation response times', isCorrect: false },
      { answerText: 'To update the IRP', isCorrect: true },
      { answerText: 'To calculate the ROI', isCorrect: false },
    ],
    explanation: 'C. To update the IRP (Incident Response Plan) Explanation: A tabletop exercise is a simulation-based activity where team members discuss their roles, responses, and strategies in a hypothetical scenario, often related to security incidents. The main goal is to assess and improve the Incident Response Plan (IRP), ensuring that all stakeholders know their roles and that the plan is up-to-date and effective in handling real-world incidents. Breakdown of the other options: A. To address audit findings: While a tabletop exercise may reveal gaps that could be addressed in audits, it is not specifically designed for this purpose. B. To collect remediation response times: Tabletop exercises are about discussing and refining processes, not directly measuring remediation times. D. To calculate the ROI (Return on Investment): ROI is not a focus of tabletop exercises, which are more concerned with improving preparedness and refining response strategies.'
  },
  {
    questionText: 'Which of the following is a use of CVSS?',
    answerOptions: [
      { answerText: 'To determine the cost associated with patching systems', isCorrect: false },
      { answerText: 'To identify unused ports and services that should be closed', isCorrect: false },
      { answerText: 'To analyze code for defects that could be exploited', isCorrect: false },
      { answerText: 'To prioritize the remediation of vulnerabilities', isCorrect: true },
    ],
    explanation: 'D. To prioritize the remediation of vulnerabilities Explanation: CVSS (Common Vulnerability Scoring System) provides a standardized way to assess the severity of vulnerabilities. It assigns a numerical score to vulnerabilities based on factors such as exploitability, impact, and the potential damage. This score helps organizations prioritize remediation efforts, ensuring that the most critical vulnerabilities are addressed first. Breakdown of the other options: A. To determine the cost associated with patching systems: CVSS does not calculate the cost of patching systems, but rather the severity of vulnerabilities. B. To identify unused ports and services that should be closed: CVSS is not used for network inventory or identifying unused services. It focuses on scoring vulnerabilities. C. To analyze code for defects that could be exploited: CVSS does not analyze code but rather scores the impact of known vulnerabilities in existing software or systems.'
  },
  {
    questionText: 'For an upcoming product launch, a company hires a marketing agency whose owner is a close relative of the Chief Executive Officer. Which of the following did the company violate?',
    answerOptions: [
      { answerText: 'Independent assessments', isCorrect: false },
      { answerText: 'Supply chain analysis', isCorrect: false },
      { answerText: 'Right-to-audit clause', isCorrect: false },
      { answerText: 'Conflict of interest policy', isCorrect: true },
    ],
    explanation: 'D. Conflict of interest policy Explanation: A conflict of interest policy is in place to ensure that business decisions are made without undue influence from personal relationships or interests. In this case, the company\'s decision to hire a marketing agency owned by a close relative of the CEO creates a conflict of interest, as it may compromise the impartiality of the decision-making process and raise concerns about favoritism or bias. Breakdown of the other options: A. Independent assessments: This is about ensuring unbiased evaluations, but the issue here is more about the personal relationship rather than an independent assessment of the product. B. Supply chain analysis: This relates to evaluating risks and dependencies within the supply chain, which doesn\'t apply to the situation of hiring the marketing agency. C. Right-to-audit clause: Refers to the ability to audit a vendor\'s activities but is unrelated to the personal conflict of interest in the hiring decision.'
  },
  {
    questionText: 'An organization designs an inbound firewall with a fail-open configuration while implementing a website. Which of the following would the organization consider to be the highest priority?',
    answerOptions: [
      { answerText: 'Confidentiality', isCorrect: false },
      { answerText: 'Non-repudiation', isCorrect: false },
      { answerText: 'Availability', isCorrect: true },
      { answerText: 'Integrity', isCorrect: false },
    ],
    explanation: 'C. Availability Explanation: A fail-open configuration means that, in the event of a failure, the firewall will allow all inbound traffic rather than blocking it. This is typically done to ensure availability, meaning that the website or service remains accessible to users even if there are issues with the firewall. The priority in this case is to avoid service disruption, ensuring the website remains available to users even during a failure scenario. Breakdown of the other options: A. Confidentiality: Protecting sensitive data is important, but in a fail-open scenario, the primary concern is ensuring that the service remains available, not necessarily confidential. B. Non-repudiation: Ensures that actions are traceable and verifiable, but it is less relevant to the firewall\'s configuration or availability. D. Integrity: While integrity is crucial to protect data from being tampered with, the fail-open configuration prioritizes availability, allowing traffic even in the event of failure.'
  },
  {
    questionText: 'An engineer needs to ensure that a script has not been modified before it is launched. Which of the following best provides this functionality?',
    answerOptions: [
      { answerText: 'Masking', isCorrect: false },
      { answerText: 'Obfuscation', isCorrect: false },
      { answerText: 'Hashing', isCorrect: true },
      { answerText: 'Encryption', isCorrect: false },
    ],
    explanation: 'C. Hashing Explanation: Hashing creates a unique fixed-size output (hash value) from the script. By calculating the hash of the original script and comparing it with the hash of the script before launch, the engineer can confirm whether the script has been modified. If the hashes match, the script is unchanged; if they differ, the script has been altered. Breakdown of the other options: A. Masking: Typically used to hide sensitive data, like credit card numbers, rather than ensuring the integrity of a script. B. Obfuscation: Involves making code difficult to understand or read, but does not guarantee that the script has not been modified. D. Encryption: Protects data confidentiality but does not inherently check for modifications; it focuses on securing data from unauthorized access.'
  },
  {
    questionText: 'Which of the following is the most important element when defining effective security governance?',
    answerOptions: [
      { answerText: 'Discovering and documenting external considerations', isCorrect: false },
      { answerText: 'Developing procedures for employee onboarding and offboarding', isCorrect: false },
      { answerText: 'Assigning roles and responsibilities for owners, controllers, and custodians', isCorrect: true },
      { answerText: 'Defining and monitoring change management procedures', isCorrect: false },
    ],
    explanation: 'C. Assigning roles and responsibilities for owners, controllers, and custodians Explanation: One of the most critical elements of effective security governance is ensuring that clear roles and responsibilities are assigned to individuals or groups within the organization, such as owners, controllers, and custodians. These roles define who is responsible for the security of data, systems, and processes, ensuring accountability and alignment with security policies and practices. Breakdown of the other options: A. Discovering and documenting external considerations: While important for risk management, external considerations are secondary to defining internal roles and responsibilities in governance. B. Developing procedures for employee onboarding and offboarding: This is essential for operational security but falls under procedural management rather than governance itself. D. Defining and monitoring change management procedures: While important for maintaining security, this is a part of operational controls rather than the core structure of security governance.'
  },
    {
      questionText: 'A contractor is required to visually inspect the motherboards of all new servers that are purchased to determine whether the servers were tampered with. Which of the following risks is the contractor attempting to mitigate?',
      answerOptions: [
        { answerText: 'Embedded rootkit', isCorrect: false },
        { answerText: 'Supply chain', isCorrect: true },
        { answerText: 'Firmware failure', isCorrect: false },
        { answerText: 'RFID keylogger', isCorrect: false },
      ],
    explanation: 'B. Supply chain Explanation: The contractor is inspecting the motherboards of new servers to ensure they have not been tampered with during the manufacturing or shipping process. This is a classic example of mitigating supply chain risks, specifically the risk of malicious modifications or unauthorized components being introduced during the supply process, which could compromise the security of the servers. Breakdown of the other options: A. Embedded rootkit: While a rootkit is a form of malware that could be installed on a device, a physical inspection of hardware is aimed at detecting hardware tampering, not malware. C. Firmware failure: This refers to issues with the device’s firmware, but inspecting the motherboard would not directly address firmware issues. D. RFID keylogger: This type of attack involves tracking or logging keystrokes via RFID, which is not directly related to inspecting motherboards for tampering.'
  },
    {
      questionText: 'Which of the following could potentially be introduced at the time of side loading?',
      answerOptions: [
        { answerText: 'User impersonation', isCorrect: false },
        { answerText: 'Rootkit', isCorrect: true },
        { answerText: 'On-path attack', isCorrect: false },
        { answerText: 'Buffer overflow', isCorrect: false },
      ],
    explanation: 'B. Rootkit Explanation: Side loading refers to the process of installing applications or software from unofficial or untrusted sources, bypassing the standard security measures of an operating system or application store. During side loading, malicious software such as a rootkit can be introduced, which allows attackers to gain deep, hidden access to the system, often with administrative privileges. Rootkits can remain undetected for long periods, enabling further malicious activity. Breakdown of the other options: A. User impersonation: This typically occurs through credential theft or social engineering, not directly due to side loading. C. On-path attack: An on-path attack (previously known as man-in-the-middle) involves intercepting communications, typically happening through network vulnerabilities, not side loading. D. Buffer overflow: While a buffer overflow is a type of software vulnerability, it is not typically introduced directly through side loading; it typically arises from poor coding practices.'
  },
    {
      questionText: 'While a school district is performing state testing, a security analyst notices all internet services are unavailable. The analyst discovers that ARP poisoning is occurring on the network and then terminates access for the host. Which of the following is most likely responsible for this malicious activity?',
      answerOptions: [
        { answerText: 'Unskilled attacker', isCorrect: false },
        { answerText: 'Shadow IT', isCorrect: false },
        { answerText: 'Insider threat', isCorrect: true },
        { answerText: 'Nation-state', isCorrect: false },
      ],
    explanation: 'sounds right. watch professor messer videos'
  },
    {
      questionText: 'A user needs to complete training at https://comptiatraining.com. After manually entering the URL, the user sees that the accessed website is noticeably different from the standard company website. Which of the following is the most likely explanation for the difference?',
      answerOptions: [
        { answerText: 'Cross-site scripting', isCorrect: false },
        { answerText: 'Pretexting', isCorrect: false },
        { answerText: 'Typosquatting', isCorrect: true },
        { answerText: 'Vishing', isCorrect: false },
      ],
    explanation: 'C. Typosquatting Explanation: Typosquatting is a form of cyber attack where an attacker registers a domain name similar to a legitimate website but with a slight typo or variation. In this case, the user manually entered the URL "https://comptiatraining.com", which is likely a misspelling or variation of a legitimate website, and was redirected to a fake website designed to look similar to the legitimate one. The noticeable difference in the website suggests that the user may have been directed to a typosquatted site that attempts to trick the user into providing sensitive information or interacting with malicious content.'
  },
    {
      questionText: 'A company has yearly engagements with a service provider. The general terms and conditions are the same for all engagements. The company wants to simplify the process and revisit the general terms every three years. Which of the following documents would provide the best way to set the general terms?',
      answerOptions: [
        { answerText: 'MSA', isCorrect: true },
        { answerText: 'NDA', isCorrect: false },
        { answerText: 'MOU', isCorrect: false },
        { answerText: 'SLA', isCorrect: false },
      ],
    explanation: 'A. MSA (Master Service Agreement) Explanation: An MSA (Master Service Agreement) is a contract that establishes the general terms and conditions for an ongoing or long-term relationship between a company and a service provider. It typically covers standard terms for multiple engagements or projects and can be revisited periodically, as in the case described (every three years), without needing to renegotiate the entire agreement each time. Breakdown of the other options: B. NDA (Non-Disclosure Agreement): An NDA is focused on protecting confidential information and does not typically govern the general terms of a business relationship. C. MOU (Memorandum of Understanding): An MOU is a non-binding document that outlines the intent to collaborate but is not typically used for establishing the detailed terms of service. D. SLA (Service Level Agreement): An SLA defines the specific performance metrics, deliverables, and quality standards for services provided but is usually a more detailed agreement tied to specific engagements, not a general framework for the entire relationship.'
  },
    {
      questionText: 'While updating the security awareness training, a security analyst wants to address issues created if vendors\' email accounts are compromised. Which of the following recommendations should the security analyst include in the training?',
      answerOptions: [
        { answerText: 'Refrain from clicking on images included in emails from new vendors', isCorrect: false },
        { answerText: 'Delete emails from unknown service provider partners.', isCorrect: false },
        { answerText: 'Require that invoices be sent as attachments', isCorrect: false },
        { answerText: 'Be alert to unexpected requests from familiar email addresses', isCorrect: true },
      ],
    explanation: 'Compromised email accounts are a common attack vector. If a vendor\'s email account is compromised, attackers may use it to send legitimate-looking, but malicious, emails. Employees should be trained to recognize unexpected requests from familiar email addresses, as this could indicate that an email is fraudulent or part of a phishing attack.'
  },
    {
      questionText: 'A new corporate policy requires all staff to use multifactor authentication to access company resources. Which of the following can be utilized to set up this form of identity and access management? (Choose two.)',
      answerOptions: [
        { answerText: 'Authentication tokens', isCorrect: true },
        { answerText: 'Least privilege', isCorrect: false },
        { answerText: 'Biometrics', isCorrect: true },
        { answerText: 'LDAP', isCorrect: false },
        { answerText: 'Password vaulting', isCorrect: false },
        { answerText: 'SAML', isCorrect: false },
      ],
    explanation: 'A. Authentication tokens C. Biometrics Explanation: Multifactor authentication (MFA) requires at least two of the following factors for user authentication: Something you know (e.g., password or PIN) Something you have (e.g., authentication token, smart card) Something you are (e.g., biometric factors like fingerprints or facial recognition) A. Authentication tokens: These are physical or software-based devices that generate or store a one-time password (OTP) to provide an additional layer of security. This is a common method used in MFA. C. Biometrics: Biometrics such as fingerprints, retina scans, or facial recognition are used as a second factor of authentication, making this a suitable option for MFA.'
  },
    {
      questionText: 'A help desk employee receives a call from someone impersonating the Chief Executive Officer. The caller asks for assistance with resetting a password. Which of the following best describes this event?',
      answerOptions: [
        { answerText: 'Vishing', isCorrect: true },
        { answerText: 'Hacktivism', isCorrect: false },
        { answerText: 'Blackmail', isCorrect: false },
        { answerText: 'Misinformation', isCorrect: false },
      ],
    explanation: 'A. Vishing Explanation: Vishing (voice phishing) is a type of social engineering attack where an attacker uses phone calls or voice messages to impersonate someone else, often with the goal of tricking the victim into providing sensitive information or performing an action like resetting a password. In this scenario, the help desk employee receives a call from someone impersonating the Chief Executive Officer (CEO) and asks for assistance with resetting a password, which is a classic vishing attack.'
  },
    {
      questionText: 'The number of tickets the help desk has been receiving has increased recently due to numerous false-positive phishing reports. Which of the following would be best to help to reduce the false positives?',
      answerOptions: [
        { answerText: 'Performing more phishing simulation campaigns', isCorrect: false },
        { answerText: 'Improving security awareness training', isCorrect: true },
        { answerText: 'Hiring more help desk staff', isCorrect: false },
        { answerText: 'Implementing an incident reporting web page', isCorrect: false },
      ],
    explanation: 'B. Improving security awareness training Explanation: False-positive phishing reports occur when employees incorrectly identify legitimate emails as phishing attempts. Improving security awareness training helps employees better recognize actual phishing emails, reducing unnecessary reports to the help desk. Training should include: ✅ How to differentiate between real and phishing emails ✅ Examples of common phishing tactics ✅ When and how to report suspicious emails Why not the others? A. Performing more phishing simulation campaigns – While simulations are helpful, they mainly test employee awareness rather than directly improving their ability to distinguish false positives. C. Hiring more help desk staff – This may address the increased workload but does not solve the root issue of frequent false-positive reports. D. Implementing an incident reporting web page – This could streamline reporting but would not necessarily reduce false positives.'
  },
    {
      questionText: 'A security report shows that during a two-week test period, 80% of employees unwittingly disclosed their SSO credentials when accessing an external website. The organization purposely created the website to simulate a cost-free password complexity test. Which of the following would best help reduce the number of visits to similar websites in the future?',
      answerOptions: [
        { answerText: 'Block all outbound traffic from the intranet.', isCorrect: false },
        { answerText: 'Introduce a campaign to recognize phishing attempts.', isCorrect: true },
        { answerText: 'Restrict internet access for the employees who disclosed credentials.', isCorrect: false },
        { answerText: 'Implement a deny list of websites.', isCorrect: false },
      ],
    explanation: 'No where in the question does it imply or state anything about email.'
  },
    {
      questionText: 'An organization that handles sensitive information wants to protect the information by using a reversible technology. Which of the following best satisfies this requirement?',
      answerOptions: [
        { answerText: 'Hardware security module', isCorrect: false },
        { answerText: 'Hashing algorithm', isCorrect: false },
        { answerText: 'Tokenization', isCorrect: true },
        { answerText: 'Steganography', isCorrect: false },
      ],
    explanation: 'C. Tokenization Explanation: Tokenization replaces sensitive data (e.g., credit card numbers, Social Security numbers) with a unique identifier (token) while storing the original data securely. The process is reversible, meaning authorized systems can retrieve the original data when needed. It is widely used in payment processing, healthcare, and financial services to protect sensitive information while maintaining usability. Why Not the Other Options? A. Hardware Security Module (HSM) → HSMs store and manage encryption keys but do not replace data with tokens. B. Hashing Algorithm → Hashing is irreversible, making it unsuitable for cases where data needs to be retrieved. D. Steganography → This hides data within files or images but does not securely protect sensitive information in a structured manner.'
  },
    {
      questionText: 'A systems administrator needs to encrypt all data on employee laptops. Which of the following encryption levels should be implemented?',
      answerOptions: [
        { answerText: 'Volume', isCorrect: false },
        { answerText: 'Partition', isCorrect: false },
        { answerText: 'Full disk', isCorrect: true },
        { answerText: 'File', isCorrect: false },
      ],
    explanation: 'C. Full disk Explanation: Full disk encryption (FDE) ensures that all data on the laptop, including the operating system, system files, and user data, is encrypted. This protects against unauthorized access in case the device is lost or stolen. Volume encryption applies to a specific logical volume, which may not cover the entire disk. Partition encryption encrypts a single partition but leaves other parts of the disk unprotected. File encryption encrypts individual files, which may leave metadata or temporary files exposed'
  },
    {
      questionText: "Which of the following actions best addresses a vulnerability found on a company's web server?",
      answerOptions: [
        { answerText: 'Patching', isCorrect: true },
        { answerText: 'Segmentation', isCorrect: false },
        { answerText: 'Decommissioning', isCorrect: false },
        { answerText: 'Monitoring', isCorrect: false },
      ],
    explanation: ''
  },
    {
      questionText: "A company is changing its mobile device policy. The company has the following requirements:\n\n• Company-owned devices\n•  Ability to harden the devices\n•  Reduced security risk\n•  Compatibility with company resources\n\nWhich of the following would best meet these requirements?",
      answerOptions: [
        { answerText: 'BYOD', isCorrect: false },
        { answerText: 'CYOD', isCorrect: false },
        { answerText: 'COPE', isCorrect: false },
        { answerText: 'COBO', isCorrect: true },
      ],
    explanation: 'COBO (Company-Owned, Business-Only) means the company fully owns and controls the devices, ensuring they can be hardened, secured, and optimized for business use. This reduces security risks and ensures full compatibility with company resources.\nCOPE (Company-Owned, Personally Enabled) allows some personal use, which might introduce security risks, though it still offers good control.\nCYOD (Choose Your Own Device) lets employees select from a list of company-approved devices but may limit security enforcement.\nBYOD (Bring Your Own Device) allows employees to use personal devices, reducing company control and increasing security risks.\n Best Choice:COBO ensures maximum security and control, making it the best fit for the company\'s requirements.'
   },
    {
      questionText: 'A company is concerned about employees unintentionally introducing malware into the network. The company identified fifty employees who clicked on a link embedded in an email sent by the internal IT department. Which of the following should the company implement to best improve its security posture?',
      answerOptions: [
        { answerText: 'Social engineering training', isCorrect: true },
        { answerText: 'SPF configuration', isCorrect: false },
        { answerText: 'Simulated phishing campaign', isCorrect: false },
        { answerText: 'Insider threat awareness', isCorrect: false },
      ],
    explanation: '(A) IT department already conducted a phishing camping , Social engineering would be best to improve security posture'
  },
    {
      questionText: 'A penetration test identifies that an SMBv1 is enabled on multiple servers across an organization. The organization wants to remediate this vulnerability in the most efficient way possible. Which of the following should the organization use for this purpose?',
      answerOptions: [
        { answerText: 'GPO', isCorrect: true },
        { answerText: 'ACL', isCorrect: false },
        { answerText: 'SFTP', isCorrect: false },
        { answerText: 'DLP', isCorrect: false },
      ],
    explanation: 'A. GPO (Group Policy Object) Explanation: SMBv1 (Server Message Block version 1) is an outdated and vulnerable protocol that is susceptible to attacks like EternalBlue, which was used in ransomware outbreaks like WannaCry. To remediate this issue efficiently across multiple servers, the best approach is to disable SMBv1 using Group Policy Objects (GPO). GPO allows administrators to enforce settings across all affected systems centrally, making it the fastest and most scalable solution.'
  },
    {
      questionText: 'Which of the following best protects sensitive data in transit across a geographically dispersed infrastructure?',
      answerOptions: [
        { answerText: 'Encryption', isCorrect: true },
        { answerText: 'Masking', isCorrect: false },
        { answerText: 'Tokenization', isCorrect: false },
        { answerText: 'Obfuscation', isCorrect: false },
      ],
    explanation: 'A. Encryption Explanation: Encryption is the process of converting data into a secure format that can only be read or decrypted by authorized parties. It protects data while it is in transit across the network, ensuring that sensitive information is not exposed even if intercepted. This is particularly important when dealing with geographically dispersed infrastructure where data might travel across various networks or regions.'
  },
    {
      questionText: 'As part of new compliance audit requirements, multiple servers need to be segmented on different networks and should be reachable only from authorized internal systems. Which of the following would meet the requirements?',
      answerOptions: [
        { answerText: 'Configure firewall rules to block external access to Internal resources.', isCorrect: false },
        { answerText: 'Set up a WAP to allow internal access from public networks.', isCorrect: false },
        { answerText: 'Implement a new IPSec tunnel from internal resources.', isCorrect: false },
        { answerText: 'Deploy an internal jump server to access resources.', isCorrect: true },
      ],
    explanation: 'isolated and authorized internal systems are the key words.'
  },
    {
      questionText: 'Which of the following activities should be performed first to compile a list of vulnerabilities in an environment?',
      answerOptions: [
        { answerText: 'Automated scanning', isCorrect: true },
        { answerText: 'Penetration testing', isCorrect: false },
        { answerText: 'Threat hunting', isCorrect: false },
        { answerText: 'Log aggregation', isCorrect: false },
        { answerText: 'Adversarial emulation', isCorrect: false },
      ],
    explanation: 'A. Automated scanning Explanation: Automated vulnerability scanning is the first step in identifying vulnerabilities across an environment. It systematically scans systems, networks, and applications for known security weaknesses, such as outdated software, misconfigurations, and missing patches. It provides a broad and efficient assessment before deeper security evaluations like penetration testing or threat hunting. Why Not the Other Options? B. Penetration testing → Penetration testing is a hands-on, targeted attack simulation, usually conducted after identifying vulnerabilities to confirm their exploitability. C. Threat hunting → This involves proactively searching for threats that have already bypassed defenses, not for general vulnerability discovery. D. Log aggregation → Collecting and analyzing logs helps with incident response and monitoring, but it does not directly identify vulnerabilities. E. Adversarial emulation → This simulates real-world attack techniques but is more advanced and comes after vulnerability identification.'
  },
    {
      questionText: 'Which of the following can be used to mitigate attacks from high-risk regions?',
      answerOptions: [
        { answerText: 'Obfuscation', isCorrect: false },
        { answerText: 'Data sovereignty', isCorrect: false },
        { answerText: 'IP geolocation', isCorrect: true },
        { answerText: 'Encryption', isCorrect: false },
      ],
    explanation: 'IP geolocation is the technique used to determine the physical location of a device based on its IP address. This can be used to block or restrict access from high-risk regions by identifying the geographic origin of incoming traffic. By using IP geolocation, an organization can filter out or limit access from countries or regions known for high levels of malicious activity or unwanted traffic. Good Luck!!! <3'
  },
    {
      questionText: "A program manager wants to ensure contract employees can only access the company's computers Monday through Friday from 9 a m. to 5 p.m. Which of the following would best enforce this access control?",
      answerOptions: [
        { answerText: 'Creating a GPO for all contract employees and setting time-of-day log-in restrictions', isCorrect: true },
        { answerText: 'Creating a discretionary access policy and setting rule-based access for contract employees', isCorrect: false },
        { answerText: 'Implementing an OAuth server and then setting least privilege for contract employees', isCorrect: false },
        { answerText: 'Implementing SAML with federation to the contract employees’ authentication server', isCorrect: false },
      ],
    explanation: ''
  },
    {
    questionText: 'After a series of account compromises and credential misuse, a company hires a security manager to develop a security program. Which of the following steps should the security manager take first to increase security awareness?',
    answerOptions: [
      { answerText: 'Evaluate tools that identify risky behavior and distribute reports on the findings.', isCorrect: false },
      { answerText: 'Send quarterly newsletters that explain the importance of password management.', isCorrect: false },
      { answerText: 'Develop phishing campaigns and notify the management team of any successes.', isCorrect: false },
      { answerText: 'Update policies and handbooks to ensure all employees are informed of the new procedures.', isCorrect: true },
    ],
    explanation: 'I go with D'
  },
    {
      questionText: 'After a series of account compromises and credential misuse, a company hires a security manager to develop a security program. Which of the following steps should the security manager take first to increase security awareness?',
      answerOptions: [
        { answerText: 'Evaluate tools that identify risky behavior and distribute reports on the findings.', isCorrect: false },
        { answerText: 'Send quarterly newsletters that explain the importance of password management.', isCorrect: false },
        { answerText: 'Develop phishing campaigns and notify the management team of any successes.', isCorrect: false },
        { answerText: 'Update policies and handbooks to ensure all employees are informed of the new procedures.', isCorrect: true },
      ],
    explanation: 'I go with D'
  },
    {
      questionText: 'Which of the following analysis methods allows an organization to measure the exposure factor associated with organizational assets?',
      answerOptions: [
        { answerText: 'Heuristic', isCorrect: false },
        { answerText: 'Quantitative', isCorrect: true },
        { answerText: 'User-driven', isCorrect: false },
        { answerText: 'Trend-based', isCorrect: false },
      ],
    explanation: 'Quantitative Explanation: Quantitative analysis involves assigning numerical values to various risk components, including exposure factor (EF), asset value (AV), single loss expectancy (SLE), and annualized loss expectancy (ALE). The exposure factor represents the percentage of asset value lost due to a specific threat event, and this is a key part of quantitative risk assessments. Other Options: A. Heuristic – Based on experience, rules of thumb, or educated guesses; not focused on measurable values. C. User-driven – Refers to methods that involve user input but not necessarily in a measurable, consistent way for exposure factor. D. Trend-based – Looks at past patterns to predict future risks but doesn\'t measure exposure factor directly. So the most appropriate choice is: B. Quantitative.'
  },
    {
      questionText: 'A security analyst notices an increase in port scans on the edge of the corporate network. Which of the following logs should the analyst check to obtain the attacker’s source IP address?',
      answerOptions: [
        { answerText: 'OS security', isCorrect: false },
        { answerText: 'Firewall', isCorrect: true },
        { answerText: 'Application', isCorrect: false },
        { answerText: 'Endpoint', isCorrect: false },
      ],
    explanation: 'B. Firewall Explanation: Firewall logs monitor and record traffic that passes through the network perimeter. They typically include source IP addresses, destination ports, protocols, and whether the traffic was allowed or blocked. Since port scans are a type of network reconnaissance, the firewall is the best place to identify external IPs attempting to scan ports. Other Options: A. OS security – Logs events on the local system (e.g., logins, policy changes), not ideal for network-level scans. C. Application – Focuses on app-specific events (e.g., errors, user activity), unlikely to capture port scans. D. Endpoint – May log network activity but usually doesn\'t capture full scan details like a perimeter firewall would. Correct answer: B. Firewall'
  },
    {
      questionText: 'A security team receives reports about high latency and complete network unavailability throughout most of the office building. Flow logs from the campus switches show high traffic on TCP 445. Which of the following is most likely the root cause of this incident?',
      answerOptions: [
        { answerText: 'Buffer overflow', isCorrect: false },
        { answerText: 'NTP amplification attack', isCorrect: false },
        { answerText: 'Worm', isCorrect: true },
        { answerText: 'DoS attack', isCorrect: false },
      ],
    explanation: 'Given the combination of widespread network impact (high latency, unavailability) and excessive traffic specifically on TCP 445, a worm is the most likely root cause. The worm would be attempting to spread by exploiting SMB, thus saturating the network with traffic on that port'
  },
    {
      questionText: 'When used with an access control vestibule which of the following would provide the best prevention against tailgating?',
      answerOptions: [
        { answerText: 'PIN', isCorrect: false },
        { answerText: 'Access card', isCorrect: false },
        { answerText: 'Security guard', isCorrect: true },
        { answerText: 'CCTV', isCorrect: false },
      ],
    explanation: 'A human guard can actively monitor behavior and intervene to stop tailgating. This provides the strongest physical enforcement of single-person entry.'
  },
    {
      questionText: 'A site reliability engineer is designing a recovery strategy that requires quick failover to an identical site if the primary facility goes down. Which of the following types of sites should the engineer consider?',
      answerOptions: [
        { answerText: 'Recovery site', isCorrect: false },
        { answerText: 'Hot site', isCorrect: true },
        { answerText: 'Cold site', isCorrect: false },
        { answerText: 'Warm site', isCorrect: false },
      ],
    explanation: 'The correct answer is: B. Hot site Here\'s the breakdown: A. Recovery site This is a general term that could refer to any kind of backup site (hot, warm, or cold). It doesn\'t specify the speed of failover or level of preparedness, so it\'s too vague for this context. B. Hot site ✅ A hot site is a fully operational, real-time mirror of the primary site. It includes hardware, software, and up-to-date data, allowing for quick failover with minimal downtime. This is exactly what the engineer needs for rapid recovery if the primary site fails. C. Cold site A cold site provides just the space and basic infrastructure, with no active systems or data. It takes a lot of time to set up and become operational after a disaster, so it’s not suitable for quick failover. D. Warm site A warm site has some equipment and data, but not up to date or fully operational. It offers moderate recovery time, but not as fast as a hot site.'
  },
    {
      questionText: 'Which of the following would an organization most likely use to minimize the loss of data on a file server in the event data needs to be restored?',
      answerOptions: [
        { answerText: 'Snapshots', isCorrect: true },
        { answerText: 'Journaling', isCorrect: false },
        { answerText: 'Obfuscation', isCorrect: false },
        { answerText: 'Tokenization', isCorrect: false },
      ],
    explanation: 'The correct answer is: A. Snapshots Here\'s why: A. Snapshots Snapshots are point-in-time copies of data on a file system or storage volume. Organizations use them to quickly restore files or entire systems to a previous state, minimizing data loss in the event of corruption, deletion, or failure. They’re commonly used for backup and recovery purposes. B. Journaling Journaling is a technique used by some file systems to keep track of changes not yet committed to the main file system. It helps prevent file system corruption, but it’s not designed for restoring lost data, just for maintaining file system integrity. C. Obfuscation Obfuscation refers to making data unclear or unreadable to unauthorized users. It’s a security/privacy technique, not a data recovery or backup method. D. Tokenization Tokenization replaces sensitive data with non-sensitive equivalents (tokens). It\'s used for data security and privacy, not for data recovery or minimizing loss.'
  },
    {
      questionText: 'Which of the following solutions would most likely be used in the financial industry to mask sensitive data?',
      answerOptions: [
        { answerText: 'Tokenization', isCorrect: true },
        { answerText: 'Hashing', isCorrect: false },
        { answerText: 'Salting', isCorrect: false },
        { answerText: 'Steganography', isCorrect: false },
      ],
    explanation: 'Replaces sensitive data with a unique, meaningless token that can be easily tracked and used in place of the original data, while keeping the actual sensitive information hidden'
  },
    {
      questionText: 'Which of the following is a type of vulnerability that may result from outdated algorithms or keys?',
      answerOptions: [
        { answerText: 'Hash collision', isCorrect: false },
        { answerText: 'Cryptographic', isCorrect: true },
        { answerText: 'Buffer overflow', isCorrect: false },
        { answerText: 'Input validation', isCorrect: false },
      ],
    explanation: 'Outdated cryptographic algorithms (e.g., DES, MD5 for security purposes) and weak or compromised keys directly lead to cryptographic vulnerabilities. These vulnerabilities make it possible for attackers to break encryption, forge digital signatures, or otherwise undermine the security properties (confidentiality, integrity, authenticity) that cryptography is supposed to provide.'
  },
    {
      questionText: 'A company wants to prevent proprietary and confidential company information from being shared to outsiders. Which of the following would this best describe?',
      answerOptions: [
        { answerText: 'MOA', isCorrect: false },
        { answerText: 'SLA', isCorrect: false },
        { answerText: 'MSA', isCorrect: false },
        { answerText: 'NDA', isCorrect: true },
      ],
    explanation: 'An NDA (Non-Disclosure Agreement) is a legal contract that prevents individuals from sharing confidential information with others.'
  },
    {
      questionText: 'A security administrator needs to reduce the attack surface in the company\'s data centers. Which of the following should the security administrator do to complete this task?',
      answerOptions: [
        { answerText: 'Implement a honeynet.', isCorrect: false },
        { answerText: 'Define Group Policy on the servers.', isCorrect: false },
        { answerText: 'Configure the servers for high availability.', isCorrect: false },
        { answerText: 'Upgrade end-of-support operating systems.', isCorrect: true },
      ],
    explanation: ''
  },
    {
      questionText: 'Which of the following is a prerequisite for a DLP solution?',
      answerOptions: [
        { answerText: 'Data destruction', isCorrect: false },
        { answerText: 'Data sanitization', isCorrect: false },
        { answerText: 'Data classification', isCorrect: true },
        { answerText: 'Data masking', isCorrect: false },
      ],
    explanation: 'Data classification: This is the process of identifying and categorizing data based on its sensitivity, value, and usage. A Data Loss Prevention (DLP) solution needs to know what data is considered sensitive to properly protect it, so data classification is a crucial prerequisite.'
  },
    {
      questionText: 'A business provides long-term cold storage services to banks that are required to follow regulator-imposed data retention guidelines. Banks that use these services require that data is disposed of in a specific manner at the conclusion of the regulatory threshold for data retention. Which of the following aspects of data management is the most important to the bank in the destruction of this data?',
      answerOptions: [
        { answerText: 'Encryption', isCorrect: false },
        { answerText: 'Classification', isCorrect: false },
        { answerText: 'Certification', isCorrect: true },
        { answerText: 'Procurement', isCorrect: false },
      ],
    explanation: 'In this scenario, the banks require that data is disposed of in a specific manner that aligns with regulatory data retention and destruction requirements. ✅ Certification in Data Destruction: Provides proof that data has been destroyed according to regulatory standards. Ensures the storage provider follows industry-accepted secure disposal practices. Helps the bank demonstrate compliance to regulators (e.g., via audit trails or destruction certificates). Can include: Certificates of Destruction (CoD) Compliance with standards like NIST SP 800-88 (media sanitization) . Encryption Protects data while stored or transmitted. ❌ Doesn’t guarantee how data is destroyed. B. Classification Labels data by sensitivity (e.g., public, confidential). ❌ Important for identifying what to destroy, but not how it\'s destroyed. D. Procurement Process of acquiring goods/services. ❌ Not related to data destruction or compliance validation.'
  },
    {
      questionText: 'The physical security team at a company receives reports that employees are not displaying their badges. The team also observes employees tailgating at controlled entrances. Which of the following topics will the security team most likely emphasize in upcoming security training?',
      answerOptions: [
        { answerText: 'Social engineering', isCorrect: false },
        { answerText: 'Situational awareness', isCorrect: true },
        { answerText: 'Phishing', isCorrect: false },
        { answerText: 'Acceptable use policy', isCorrect: false },
      ],
    explanation: 'Correct Answer: A Explanation Explanation/Reference: Social engineering attacks exploit human behavior to bypass security controls. Tailgating (following an authorized person into a restricted area without authentication) and badge non-compliance are common tactics used by attackers to gain unauthorized physical access. Training employees to recognize and prevent social engineering tactics can reduce these risks. Situational awareness (B) relates to general security awareness but is not specific to social engineering attacks. Phishing (C) targets victims via email or online deception, not physical access. Acceptable use policy (D) defines how employees should use IT resources but does not address physical security risks. Reference:CompTIA Security+ SY0-701 Official Study Guide, General Security Concepts domain.'
  },
    {
      questionText: 'Which of the following would most likely be a hacktivist\'s motive?',
      answerOptions: [
        { answerText: 'Financial gain', isCorrect: false },
        { answerText: 'Espionage', isCorrect: false },
        { answerText: 'Philosophical beliefs', isCorrect: true },
        { answerText: 'Revenge', isCorrect: false },
      ],
    explanation: 'Hacktivism is typically driven by strong political or social beliefs, where individuals use their hacking skills to promote a cause or protest against issues they feel are unjust.'
  },
    {
      questionText: 'During a recent log review, an analyst discovers evidence of successful injection attacks. Which of the following will best address this issue?',
      answerOptions: [
        { answerText: 'Authentication', isCorrect: false },
        { answerText: 'Secure cookies', isCorrect: false },
        { answerText: 'Static code analysis', isCorrect: false },
        { answerText: 'Input validation', isCorrect: true },
      ],
    explanation: 'Injection attacks occur when attackers exploit vulnerabilities in applications to inject malicious code. This code can then execute unauthorized commands, access sensitive data, or manipulate the system\'s operations. Input validation is a security measure that checks user input for any harmful or invalid data before it is processed by the application. By validating input, developers can prevent attackers from injecting malicious code into their systems.'
  },
    {
      questionText: 'Which of the following is the first step to secure a newly deployed server?',
      answerOptions: [
        { answerText: 'Close unnecessary service ports.', isCorrect: true },
        { answerText: 'Update the current version of the software.', isCorrect: false },
        { answerText: 'Add the device to the ACL.', isCorrect: false },
        { answerText: 'Upgrade the OS version.', isCorrect: false },
      ],
    explanation: 'Before configuring ports, permissions or network rules, it is essential to ensure that the system is up to date, including with the latest version of the operating system, which corrects known vulnerabilities.'
  },
    {
      questionText: 'A security analyst receives an alert that there was an attempt to download known malware. Which of the following actions would allow the best chance to analyze the malware?',
      answerOptions: [
        { answerText: 'Review the IPS logs and determine which command-and-control IPs were blocked.', isCorrect: false },
        { answerText: 'Analyze application logs to see how the malware attempted to maintain persistence.', isCorrect: false },
        { answerText: 'Run vulnerability scans to check for systems and applications that are vulnerable to the malware', isCorrect: false },
        { answerText: 'Obtain and execute the malware in a sandbox environment and perform packet captures.', isCorrect: true },
      ],
    explanation: 'A sandbox is a isolated environment where you can safely run suspicious files without affecting your actual system. This allows the analyst to observe the malware\'s behavior and behavior without risking harm to the system'
  },
    {
      questionText: 'Which of the following should be used to ensure a user has the permissions needed to effectively do an assigned job role?',
      answerOptions: [
        { answerText: 'Changing default passwords', isCorrect: false },
        { answerText: 'Implementing least privilege', isCorrect: true },
        { answerText: 'Enforcing baseline configurations', isCorrect: false },
        { answerText: 'Applying network segmentation', isCorrect: false },
      ],
    explanation: '"Implementing least privilege": means granting users only the minimum level of access needed to perform their job functions, which minimizes the risk of unauthorized access or data breaches if their account is compromised.'
  },
    {
      questionText: 'An employee receives a text message from an unrecognized number claiming to be the Chief Executive Officer and asking the employee to purchase gift cards. Which of the following types of attacks describes this example?',
      answerOptions: [
        { answerText: 'Watering-hole', isCorrect: false },
        { answerText: 'Disinformation', isCorrect: false },
        { answerText: 'Phishing', isCorrect: false },
        { answerText: 'Impersonation', isCorrect: true },
      ],
    explanation: 'The correct answer is: D. Impersonation Explanation: Impersonation is when an attacker pretends to be someone else, such as a CEO, to trick the victim into taking an action — in this case, purchasing gift cards.'
  },
    {
      questionText: "An unexpected and out-of-character email message from a Chief Executive Officer's corporate account asked an employee to provide financial information and to change the recipient's contact number. Which of the following attack vectors is most likely being used?",
      answerOptions: [
        { answerText: 'Business email compromise', isCorrect: true },
        { answerText: 'Phishing', isCorrect: false },
        { answerText: 'Brand impersonation', isCorrect: false },
        { answerText: 'Pretexting', isCorrect: false },
      ],
    explanation: 'Business Email Compromise (BEC) is a targeted attack where the attacker gains access to a legitimate business email account (like a CEO\'s) and uses it to deceive employees into transferring money, revealing sensitive information, or changing account details.'
  },
    {
      questionText: 'Which of the following should an organization use to ensure that it can review the controls and performance of a service provider or vendor?',
      answerOptions: [
        { answerText: 'Service-level agreement', isCorrect: false },
        { answerText: 'Memorandum of agreement', isCorrect: false },
        { answerText: 'Right-to-audit clause', isCorrect: true },
        { answerText: 'Supply chain analysis', isCorrect: false },
      ],
    explanation: 'i agree with Shanu007 c'
  },
    {
      questionText: 'Which of the following is used to calculate the impact to an organization per cybersecurity incident?',
      answerOptions: [
        { answerText: 'SLE', isCorrect: true },
        { answerText: 'ALE', isCorrect: false },
        { answerText: 'ARO', isCorrect: false },
        { answerText: 'SLA', isCorrect: false },
      ],
    explanation: 'SLE is specifically used to calculate per-incident financial impact, making A the correct answer.'
  },
    {
      questionText: "A retail company receives a request to remove a customer's data. Which of the following is the retail company considered under GDPR legislation?",
      answerOptions: [
        { answerText: 'Data processor', isCorrect: false },
        { answerText: 'Data controller', isCorrect: true },
        { answerText: 'Data subject', isCorrect: false },
        { answerText: 'Data custodian', isCorrect: false },
      ],
    explanation: 'Under the General Data Protection Regulation (GDPR): A Data Controller is the entity that determines the purpose and means of processing personal data.\nIn this case, the retail company decides how and why customer data is collected, stored, and used.\n Therefore, the company is the Data Controller and is responsible for honoring requests like data deletion (right to be forgotten).'
  },
    {
      questionText: 'An administrator implements web-filtering products but still sees that users are visiting malicious links. Which of the following configuration items does the security administrator need to review?',
      answerOptions: [
        { answerText: 'Intrusion prevention system', isCorrect: false },
        { answerText: 'Content categorization', isCorrect: true },
        { answerText: 'Encryption', isCorrect: false },
        { answerText: 'DNS service', isCorrect: false },
      ],
    explanation: 'Category Filtering: Web filters often categorize websites (e.g., social media, gaming, adult content). The administrator needs to ensure the categories are configured appropriately and that the filter is blocking the intended categories. Overly broad or inaccurate categories can lead to unintended blocking or allowed access.'
  },
    {
      questionText: "A security analyst is reviewing the following logs about a suspicious activity alert for a user's VPN log-ins:Which of the following malicious activity indicators triggered the alert?",
      answerOptions: [
        { answerText: 'Impossible travel', isCorrect: true },
        { answerText: 'Account lockout', isCorrect: false },
        { answerText: 'Blocked content', isCorrect: false },
        { answerText: 'Concurrent session usage', isCorrect: false },
      ],
    explanation: 'This indicator is triggered when a user logs in from two geographically distant locations within an impossibly short period of time. Looking at the VPN log ins, the user logged in from Chicago at 8:22am on 01/27 and logged in shortly after from Rome-Italy at 9:45am on the same date. That can\'t be possible!'
  },
    {
      questionText: 'Which of the following phases of the incident response process attempts to minimize disruption?',
      answerOptions: [
        { answerText: 'Recovery', isCorrect: false },
        { answerText: 'Containment', isCorrect: true },
        { answerText: 'Preparation', isCorrect: false },
        { answerText: 'Analysis', isCorrect: false },
      ],
     explanation: 'after reseatch i agree B is the answer'
    },
  ];

const QUESTIONS_PER_QUIZ = 90;
const QUIZ_DURATION_SECONDS = 90 * 60;
const PASSING_SCORE = 750;

// =================================================================================
// === HELPER FUNCTIONS ============================================================
// =================================================================================
const formatTime = (seconds) => {
  const minutes = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return `${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
};

const getScoreMessage = (score) => {
    if (score >= PASSING_SCORE) {
        return { message: "Congratulations, you passed!", color: "text-green-600" };
    } else if (score >= 600) {
        return { message: "You're so close! A little more review and you'll nail it next time.", color: "text-orange-500" };
    } else if (score >= 400) {
        return { message: "Good effort! Keep reviewing the key concepts to build your confidence.", color: "text-blue-500" };
    } else {
        return { message: "A great first step! Every review session helps you learn more.", color: "text-gray-600" };
    }
};


// =================================================================================
// === CHILD COMPONENTS ============================================================
// =================================================================================

const LandingPage = ({ onStart, onShowHistory }) => (
    <div className="text-center flex flex-col justify-center items-center h-full">
      <h1 className="text-4xl font-bold text-gray-800 mb-4">Welcome to CompTIA SY0-701 Exam Reviewer!</h1>
      <p className="text-lg text-gray-600 mb-2">
        You will be given <span className="font-bold">{Math.min(QUESTIONS_PER_QUIZ, masterQuestions.length)}</span> random questions.
      </p>
       <p className="text-lg text-gray-600 mb-2">
        You have <span className="font-bold">90 minutes</span> to complete the quiz.
      </p>
      <p className="text-lg text-gray-600 mb-8">
        A score of <span className="font-bold">{PASSING_SCORE}</span> or higher is required to pass. Good luck!
      </p>
      <div className="flex gap-4">
        <button
          onClick={onStart}
          className="bg-green-600 hover:bg-green-700 text-white font-bold py-4 px-10 rounded-full shadow-xl transition duration-300 ease-in-out transform hover:scale-105 focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-opacity-75"
        >
          Start Quiz
        </button>
        <button
          onClick={onShowHistory}
          className="bg-gray-500 hover:bg-gray-600 text-white font-bold py-4 px-10 rounded-full shadow-xl transition duration-300 ease-in-out transform hover:scale-105 focus:outline-none focus:ring-2 focus:ring-gray-400 focus:ring-opacity-75"
        >
          View History
        </button>
      </div>
    </div>
);

const ScoreScreen = ({ score, rawScore, totalQuestions, questions, userAnswers, onRestart, onShowHistory, onBackToHome, onRestartFromHistory, reviewFilter, setReviewFilter, searchTerm, setSearchTerm, isSearchVisible, setIsSearchVisible, filteredQuestions, explanationVisibility, toggleExplanation, questionPoolLength, isReviewVisible, setIsReviewVisible }) => {
    const { message, color } = getScoreMessage(score);

    const handleFilterClick = (filter) => {
        if (isReviewVisible && reviewFilter === filter) {
            setIsReviewVisible(false);
        } else {
            setReviewFilter(filter);
            setIsReviewVisible(true);
        }
    };

    const handleDownloadPdf = () => {
        if (!window.jspdf) {
            alert("PDF library is not loaded yet. Please try again in a moment.");
            return;
        }
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF({ unit: 'pt', format: 'a4' });
        let y = 40;
        const pageMargin = 40;
        const pageWidth = doc.internal.pageSize.getWidth();
        const contentWidth = pageWidth - (pageMargin * 2);

        const addText = (text, x, yPos, options = {}) => {
            const { size = 10, style = 'normal', color = '#000000' } = options;
            doc.setFontSize(size);
            doc.setFont('helvetica', style);
            doc.setTextColor(color);

            const splitText = doc.splitTextToSize(text, contentWidth - (x - pageMargin));
            
            if (yPos + (splitText.length * (size * 1.2)) > doc.internal.pageSize.getHeight() - pageMargin) {
                doc.addPage();
                yPos = pageMargin;
            }
            doc.text(splitText, x, yPos);
            return yPos + (splitText.length * (size * 1.2));
        };

        doc.setFontSize(22);
        doc.setFont('helvetica', 'bold');
        doc.text("Quiz Review", pageWidth / 2, y, { align: "center" });
        y += 30;

        filteredQuestions.forEach((question, idx) => {
            const originalQuestionIndex = questions.findIndex(q => q.questionText === question.questionText);
            
            if (y > doc.internal.pageSize.getHeight() - 100) { // Check for space before starting new question
                doc.addPage();
                y = pageMargin;
            }

            // Question Text
            y = addText(`${originalQuestionIndex + 1}. ${question.questionText.replace(/\n\n/g, '\n')}`, pageMargin, y, { size: 12, style: 'bold' });
            y += 5;

            // Answer Options
            question.answerOptions.forEach((option, optionIndex) => {
                const isUserAnswer = userAnswers[originalQuestionIndex] && userAnswers[originalQuestionIndex].includes(optionIndex);
                const isCorrectAnswer = option.isCorrect;
                
                let prefix = '';
                let textColor = '#374151'; // gray-700
                
                if (isCorrectAnswer) {
                    prefix = '✓ ';
                    textColor = '#166534'; // green-800
                }
                if (isUserAnswer && !isCorrectAnswer) {
                    prefix = '✗ ';
                    textColor = '#991b1b'; // red-800
                }
                
                let fullText = `${String.fromCharCode(65 + optionIndex)}. ${prefix}${option.answerText}`;
                if (isUserAnswer) {
                    fullText += ' (Your Answer)';
                }

                y = addText(fullText, pageMargin + 15, y, { size: 10, color: textColor });
            });
            
            // Explanation
            if (question.explanation) {
                y += 10;
                if (y > doc.internal.pageSize.getHeight() - 40) {
                    doc.addPage();
                    y = pageMargin;
                }
                doc.setFillColor(243, 244, 246); // gray-100
                doc.setDrawColor(209, 213, 219); // gray-300
                
                const explanationLines = doc.splitTextToSize(question.explanation, contentWidth - 20);
                const explanationHeight = (explanationLines.length * 10) + 20;

                doc.rect(pageMargin, y, contentWidth, explanationHeight, 'FD');
                y = addText('Explanation:', pageMargin + 10, y + 15, { size: 10, style: 'bold' });
                y = addText(question.explanation, pageMargin + 10, y, { size: 10, color: '#1f2937' }); // gray-800
                y += 10;
            }

            y += 20; // Space between questions
        });

        doc.save('quiz-review.pdf');
    };

    return (
        <div className="text-center">
          <h2 className="text-3xl font-bold text-gray-800 mb-2">{onBackToHome ? 'Reviewing Past Quiz' : 'Quiz Completed!'}</h2>
          
          <div className="my-6 p-6 rounded-lg bg-gray-100 shadow-inner">
            <p className="text-xl text-gray-600 mb-2">Your Score</p>
            <p className="text-6xl font-bold text-purple-700">{score}</p>
            <p className="text-lg text-gray-500 mt-2">(Scaled from 100 to 900)</p>
          </div>

          <p className={`text-2xl font-bold mb-4 ${color}`}>{message}</p>

          <p className="text-xl text-gray-700 mb-6">
            You earned {rawScore.toFixed(2)} out of {totalQuestions} possible points.
          </p>

          <div className="flex flex-wrap justify-center gap-4">
              {onRestart && <button
                onClick={onRestart}
                className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-6 rounded-full shadow-lg transition duration-300 ease-in-out transform hover:scale-105 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-opacity-75"
              >
                {questionPoolLength < QUESTIONS_PER_QUIZ ? 'Restart with All Questions' : 'Try New Questions'}
              </button>}
              {onShowHistory && <button
                onClick={onShowHistory}
                className="bg-gray-500 hover:bg-gray-600 text-white font-bold py-3 px-6 rounded-full shadow-lg transition duration-300 ease-in-out transform hover:scale-105 focus:outline-none focus:ring-2 focus:ring-gray-400 focus:ring-opacity-75"
              >
                View History
              </button>}
              {onBackToHome && (
                <>
                    <button onClick={onBackToHome} className="bg-gray-500 hover:bg-gray-600 text-white font-bold py-3 px-6 rounded-full shadow-lg transition duration-300 ease-in-out transform hover:scale-105 focus:outline-none focus:ring-2 focus:ring-gray-400 focus:ring-opacity-75">
                        Back to History
                    </button>
                    <button onClick={onRestartFromHistory} className="bg-green-600 hover:bg-green-700 text-white font-bold py-3 px-6 rounded-full shadow-lg transition duration-300 ease-in-out transform hover:scale-105 focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-opacity-75">
                        Restart This Quiz
                    </button>
                </>
              )}
              <button onClick={handleDownloadPdf} className="bg-teal-500 hover:bg-teal-600 text-white font-bold py-3 px-6 rounded-full shadow-lg transition duration-300 ease-in-out transform hover:scale-105 focus:outline-none focus:ring-2 focus:ring-teal-400 focus:ring-opacity-75">
                Download PDF
              </button>
          </div>
          <div className="mt-8 text-left">
            <div className="flex flex-col sm:flex-row justify-between items-center mb-4 border-b-2 border-gray-200 pb-4 gap-4">
                <div className="flex gap-2">
                    <button onClick={() => handleFilterClick('all')} className={`px-4 py-2 rounded-lg font-semibold ${reviewFilter === 'all' && isReviewVisible ? 'bg-blue-500 text-white' : 'bg-gray-200 text-gray-700'}`}>All</button>
                    <button onClick={() => handleFilterClick('incorrect')} className={`px-4 py-2 rounded-lg font-semibold ${reviewFilter === 'incorrect' && isReviewVisible ? 'bg-blue-500 text-white' : 'bg-gray-200 text-gray-700'}`}>Incorrect</button>
                </div>
                <div className="relative flex items-center">
                    <input 
                        type="text"
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        placeholder="Search..."
                        className={`p-2 pl-10 border-2 border-gray-300 rounded-full focus:outline-none focus:ring-2 focus:ring-blue-400 transition-all duration-300 ease-in-out ${isSearchVisible ? 'w-48 md:w-64' : 'w-0'}`}
                        style={{ paddingRight: isSearchVisible ? '2.5rem' : '0' }}
                    />
                    <button onClick={() => setIsSearchVisible(!isSearchVisible)} className="absolute right-0 p-2 bg-transparent rounded-full hover:bg-gray-200">
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                        </svg>
                    </button>
                </div>
            </div>

            {isReviewVisible && filteredQuestions.map((question, index) => {
                const originalQuestionIndex = questions.findIndex(q => q.questionText === question.questionText);
                return (
                  <div key={index} id={`review-card-${originalQuestionIndex}`} className="mb-6 p-4 border border-gray-200 rounded-lg bg-gray-50 scroll-mt-4">
                    <p className="font-medium text-lg text-gray-900 mb-2 whitespace-pre-wrap">
                      {originalQuestionIndex + 1}. {question.questionText}
                    </p>
                    <ul className="flex flex-col gap-2">
                      {question.answerOptions.map((option, optionIndex) => {
                        const isUserAnswer = userAnswers[originalQuestionIndex] && userAnswers[originalQuestionIndex].includes(optionIndex);
                        const isCorrectAnswer = option.isCorrect;
                        let styleClass = 'bg-white border-gray-300 text-gray-800';
                        let label = null;

                        if (isCorrectAnswer) {
                            styleClass = 'bg-green-100 border-green-400 text-green-800';
                            label = <span className="ml-auto pl-4 font-semibold">Correct Answer</span>;
                        }
                        if (isUserAnswer) {
                            if (isCorrectAnswer) {
                                label = (
                                    <div className="ml-auto pl-4 flex flex-col items-end text-right">
                                        <span className="font-semibold text-green-700">Correct Answer</span>
                                        <span className="font-semibold text-blue-700 text-sm">(Your Answer)</span>
                                    </div>
                                );
                            } else {
                                styleClass = 'bg-red-100 border-red-400 text-red-800';
                                label = <span className="ml-auto pl-4 font-semibold">Your Answer</span>;
                            }
                        }
                        
                        return (
                          <li key={optionIndex} className={`p-2 md:p-3 rounded-lg border-2 flex items-center ${styleClass}`}>
                            <span className="mr-3 font-bold h-6 w-6 flex items-center justify-center rounded-full bg-gray-300 text-gray-700">{String.fromCharCode(65 + optionIndex)}</span>
                            <span className="flex-grow">{option.answerText}</span>
                            {label}
                          </li>
                        );
                      })}
                    </ul>
                    {question.explanation && (
                        <div className="mt-4 text-left">
                            <button onClick={() => toggleExplanation(originalQuestionIndex)} className="inline-flex items-center gap-2 text-sm text-gray-600 hover:text-gray-800 font-semibold py-2 px-4 rounded-full bg-gray-200 hover:bg-gray-300 transition-colors shadow-sm">
                                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-yellow-500 group-hover:text-yellow-400 transition-colors" viewBox="0 0 20 20" fill="currentColor">
                                  <path d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm-7.071 0a1 1 0 001.414 1.414l.707-.707a1 1 0 10-1.414-1.414l-.707.707zM10 16a1 1 0 100 2 1 1 0 000-2z" />
                                </svg>
                                {explanationVisibility[originalQuestionIndex] ? 'Hide' : 'Show'} Explanation
                            </button>
                            {explanationVisibility[originalQuestionIndex] && (
                                <div className="mt-3 p-4 bg-gray-50 border-l-4 border-gray-400 text-gray-800">
                                    <p className="font-bold">Explanation</p>
                                    <p className="mt-1 whitespace-pre-wrap">{question.explanation}</p>
                                </div>
                            )}
                        </div>
                    )}
                  </div>
                )
            })}
             {isReviewVisible && <div className="mt-8 pt-4 border-t-2 border-gray-200">
                <h3 className="text-lg font-semibold text-gray-700 mb-3 text-center">Jump to Question</h3>
                <div className="flex flex-wrap gap-2 justify-center">
                    {questions.map((question, index) => {
                        const correctIndices = new Set(question.answerOptions.map((opt, i) => opt.isCorrect ? i : -1).filter(i => i !== -1));
                        const userIndices = new Set(userAnswers[index] || []);
                        
                        let isCorrect = false;
                        if (correctIndices.size > 0 && correctIndices.size === userIndices.size) {
                            isCorrect = [...userIndices].every(i => correctIndices.has(i));
                        }

                        const navButtonClass = isCorrect ? 'bg-green-500 hover:bg-green-600' : 'bg-red-500 hover:bg-red-600';

                        const handleNavClick = () => {
                            const element = document.getElementById(`review-card-${index}`);
                            if (element) {
                                element.scrollIntoView({ behavior: 'smooth', block: 'center' });
                            }
                        };
                        
                        return (
                            <button
                                key={index}
                                onClick={handleNavClick}
                                className={`h-10 w-10 flex items-center justify-center font-bold rounded-md text-white transition-colors duration-200 ${navButtonClass}`}
                            >
                                {index + 1}
                            </button>
                        );
                    })}
                </div>
            </div>}
          </div>
        </div>
    );
  };

  const QuestionView = ({ currentQuestionData, currentQuestionIndex, totalQuestions, userAnswers, onAnswer, onFlag, onNext, onPrev, onSubmit, flaggedQuestions, timeLeft, showSubmitConfirm, setShowSubmitConfirm, setCurrentQuestion }) => {
    const mainContentRef = useRef(null);
    useEffect(() => {
        if(mainContentRef.current) {
            mainContentRef.current.scrollTop = 0;
        }
    }, [currentQuestionIndex]);

    return (
    <div className="relative" ref={mainContentRef}>
      <div className="pb-28 md:pb-0">
          <div className="flex justify-between items-center mb-6">
            <div className="text-xl font-semibold text-gray-600">
              <span>Question {currentQuestionIndex + 1}</span>/{totalQuestions}
            </div>
            <div className="text-2xl font-bold text-purple-700 bg-purple-100 px-4 py-2 rounded-lg shadow-inner">
              {formatTime(timeLeft)}
            </div>
          </div>
          <div className="text-lg font-medium text-gray-800 mt-3 mb-6 text-left whitespace-pre-wrap">
            {currentQuestionData.questionText}
          </div>
          <div className="flex flex-col gap-3">
            {currentQuestionData.answerOptions.map((answerOption, index) => {
              const isSelected = userAnswers[currentQuestionIndex] && userAnswers[currentQuestionIndex].includes(index);
              let buttonClass = 'bg-white hover:bg-gray-100 text-gray-800 border-gray-300';
              if (isSelected) buttonClass = 'bg-blue-100 text-blue-800 border-blue-400';

              return (
                <button
                  key={index}
                  onClick={() => onAnswer(index)}
                  className={`w-full font-medium py-3 px-4 rounded-lg border-2 transition duration-200 ease-in-out transform focus:outline-none focus:ring-2 focus:ring-opacity-75 ${buttonClass} hover:scale-102 cursor-pointer text-left flex items-center`}
                >
                  <span className="mr-3 font-bold h-6 w-6 flex items-center justify-center rounded-full bg-gray-200 text-gray-700">{String.fromCharCode(65 + index)}</span>
                  <span>{answerOption.answerText}</span>
                </button>
              );
            })}
          </div>
          
          <div className="mt-8 flex justify-between items-center">
              <button
                  onClick={onFlag}
                  className={`font-bold py-3 px-5 md:py-3 md:px-6 text-sm md:text-base rounded-full shadow-lg transition duration-300 ease-in-out transform hover:scale-105 focus:outline-none focus:ring-2 focus:ring-opacity-75 ${flaggedQuestions[currentQuestionIndex] ? 'bg-yellow-500 hover:bg-yellow-600 text-white focus:ring-yellow-400' : 'bg-yellow-300 hover:bg-yellow-400 text-yellow-800 focus:ring-yellow-300'}`}
              >
                  {flaggedQuestions[currentQuestionIndex] ? 'Unflag' : 'Flag'}
              </button>
              <div className="flex gap-2 md:gap-4">
                  {currentQuestionIndex > 0 && (
                       <button
                          onClick={onPrev}
                          className="bg-gray-500 hover:bg-gray-600 text-white font-bold py-3 px-5 md:py-3 md:px-8 text-sm md:text-base rounded-full shadow-lg transition duration-300 ease-in-out transform hover:scale-105 focus:outline-none focus:ring-2 focus:ring-gray-400 focus:ring-opacity-75"
                      >
                          Back
                      </button>
                  )}
                <button
                  onClick={onNext}
                  className="bg-purple-600 hover:bg-purple-700 text-white font-bold py-3 px-5 md:py-3 md:px-8 text-sm md:text-base rounded-full shadow-lg transition duration-300 ease-in-out transform hover:scale-105 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:ring-opacity-75"
                >
                  {currentQuestionIndex === totalQuestions - 1 ? 'Submit' : 'Next'}
                </button>
              </div>
          </div>

          <div className="mt-8 pt-4 border-t-2 border-gray-200">
              <h3 className="text-lg font-semibold text-gray-700 mb-3 text-center">Question Navigator</h3>
              <div className="flex flex-wrap gap-2 justify-center">
                  {Array.from({ length: totalQuestions }).map((_, index) => {
                      const isAnswered = userAnswers[index] && userAnswers[index].length > 0;
                      const isCurrent = index === currentQuestionIndex;
                      const isFlagged = flaggedQuestions[index];
                      
                      let navButtonClass = 'bg-gray-200 hover:bg-gray-300 text-gray-700'; // Default
                      if (isFlagged) {
                          navButtonClass = 'bg-red-500 hover:bg-red-600 text-white';
                      } else if (isAnswered) {
                          navButtonClass = 'bg-green-500 hover:bg-green-600 text-white';
                      }

                      if (isCurrent) {
                          navButtonClass = 'bg-blue-500 text-white ring-2 ring-offset-2 ring-blue-500'; // Current overrides other colors
                      }
                      
                      return (
                          <button
                              key={index}
                              onClick={() => setCurrentQuestion(index)}
                              className={`h-10 w-10 flex items-center justify-center font-bold rounded-md transition-colors duration-200 ${navButtonClass}`}
                          >
                              {index + 1}
                          </button>
                      );
                  })}
              </div>
          </div>
      </div>
    </div>
  );
};

const FinalReviewScreen = ({ flaggedQuestions, unansweredQuestions, onGoToQuestion, onSubmitFinal }) => (
    <div className="p-4 md:p-8">
        <h2 className="text-3xl font-bold text-gray-800 mb-6 text-center">Final Review</h2>
        
        <div className="mb-8">
            <h3 className="text-xl font-semibold text-gray-700 mb-3">Flagged Questions</h3>
            {flaggedQuestions.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                    {flaggedQuestions.map(qIndex => (
                        <button key={`flagged-${qIndex}`} onClick={() => onGoToQuestion(qIndex)} className="h-10 w-10 flex items-center justify-center font-bold rounded-md text-white bg-yellow-500 hover:bg-yellow-600 transition-colors">
                            {qIndex + 1}
                        </button>
                    ))}
                </div>
            ) : (
                <p className="text-gray-500">No questions flagged for review.</p>
            )}
        </div>

        <div className="mb-8">
            <h3 className="text-xl font-semibold text-gray-700 mb-3">Unanswered Questions</h3>
            {unansweredQuestions.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                    {unansweredQuestions.map(qIndex => (
                        <button key={`unanswered-${qIndex}`} onClick={() => onGoToQuestion(qIndex)} className="h-10 w-10 flex items-center justify-center font-bold rounded-md text-white bg-gray-400 hover:bg-gray-500 transition-colors">
                            {qIndex + 1}
                        </button>
                    ))}
                </div>
            ) : (
                <p className="text-gray-500">All questions have been answered.</p>
            )}
        </div>

        <div className="mt-12 text-center">
            <button onClick={onSubmitFinal} className="bg-green-600 hover:bg-green-700 text-white font-bold py-4 px-10 rounded-full shadow-xl transition duration-300 ease-in-out transform hover:scale-105 focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-opacity-75">
                Submit Final Answers
            </button>
        </div>
    </div>
);

// Main App component
const App = () => {
    const [quizStarted, setQuizStarted] = useState(false);
    const [currentQuestion, setCurrentQuestion] = useState(0);
    const [showScore, setShowScore] = useState(false);
    const [rawScore, setRawScore] = useState(0);
    const [scaledScore, setScaledScore] = useState(0);
    const [userAnswers, setUserAnswers] = useState([]);
    const [timeLeft, setTimeLeft] = useState(QUIZ_DURATION_SECONDS);
    const [isQuizActive, setIsQuizActive] = useState(false);
    const [flaggedQuestions, setFlaggedQuestions] = useState([]);
    const [searchTerm, setSearchTerm] = useState('');
    const [filteredQuestions, setFilteredQuestions] = useState([]);
    const [isSearchVisible, setIsSearchVisible] = useState(false);
    const [reviewFilter, setReviewFilter] = useState('all');
    const [showFinalReviewScreen, setShowFinalReviewScreen] = useState(false);
    const [explanationVisibility, setExplanationVisibility] = useState({});
    const [scoreHistory, setScoreHistory] = useState([]);
    const [isHistoryVisible, setIsHistoryVisible] = useState(false);
    const [reviewingHistoryEntry, setReviewingHistoryEntry] = useState(null);
    const [isReviewVisible, setIsReviewVisible] = useState(false);
    
    const [questionPool, setQuestionPool] = useState(() => [...masterQuestions.keys()]);
    const [currentQuizQuestions, setCurrentQuizQuestions] = useState([]);

    useEffect(() => {
        try {
            const savedScores = localStorage.getItem('quizScoreHistory');
            if (savedScores) {
                setScoreHistory(JSON.parse(savedScores));
            }
        } catch (error) {
            console.error("Could not parse score history:", error);
            setScoreHistory([]);
        }
    }, []);
    
    useEffect(() => {
        const script = document.createElement('script');
        script.src = "https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js";
        script.async = true;
        document.body.appendChild(script);
        return () => {
            document.body.removeChild(script);
        }
    }, []);
    
    const shuffleArray = (array) => {
        let currentIndex = array.length, randomIndex;
        while (currentIndex !== 0) {
            randomIndex = Math.floor(Math.random() * currentIndex);
            currentIndex--;
            [array[currentIndex], array[randomIndex]] = [array[randomIndex], array[currentIndex]];
        }
        return array;
    };

    const setupNewQuiz = (questions) => {
        setCurrentQuizQuestions(questions);
        setUserAnswers(Array(questions.length).fill(null).map(() => []));
        setFlaggedQuestions(Array(questions.length).fill(false));
        setExplanationVisibility({});
        setCurrentQuestion(0);
        setTimeLeft(QUIZ_DURATION_SECONDS);
        setQuizStarted(true);
        setShowScore(false);
        setIsQuizActive(true);
        setReviewingHistoryEntry(null);
    };
    
    const calculateFinalScore = useCallback(() => {
        let totalPoints = 0;
        userAnswers.forEach((selectedIndices, questionIndex) => {
          const question = currentQuizQuestions[questionIndex];
          const correctOptionIndices = question.answerOptions
            .map((option, index) => (option.isCorrect ? index : -1))
            .filter(index => index !== -1);
          
          const userSelectedIndices = selectedIndices || [];
    
          const correctAnswersSelected = userSelectedIndices.filter(selectedIndex => 
            correctOptionIndices.includes(selectedIndex)
          ).length;
          
          if (correctOptionIndices.length > 0) {
              const pointsForThisQuestion = correctAnswersSelected / correctOptionIndices.length;
              totalPoints += pointsForThisQuestion;
          }
        });
    
        setRawScore(totalPoints);
    
        const totalQuestions = currentQuizQuestions.length;
        let finalScaledScore = 100;
        if (totalQuestions > 0) {
            finalScaledScore = Math.round(((totalPoints / totalQuestions) * 800) + 100);
            setScaledScore(finalScaledScore);
        } else {
            setScaledScore(100);
        }
        
        const newScoreEntry = {
            id: Date.now(),
            score: finalScaledScore,
            date: new Date().toLocaleString(),
            questions: currentQuizQuestions,
            userAnswers: userAnswers,
            rawScore: totalPoints,
            totalQuestions: totalQuestions,
        };
        setScoreHistory(prevHistory => {
            const updatedHistory = [newScoreEntry, ...prevHistory];
            localStorage.setItem('quizScoreHistory', JSON.stringify(updatedHistory));
            return updatedHistory;
        });
    }, [userAnswers, currentQuizQuestions]);
      
    useEffect(() => {
        const sourceQuestions = reviewingHistoryEntry ? reviewingHistoryEntry.questions : currentQuizQuestions;
        const sourceAnswers = reviewingHistoryEntry ? reviewingHistoryEntry.userAnswers : userAnswers;

        if (showScore || reviewingHistoryEntry) {
            let questionsToDisplay = [...sourceQuestions];

            if (reviewFilter === 'incorrect') {
                questionsToDisplay = questionsToDisplay.filter((question, index) => {
                    const correctIndices = new Set(question.answerOptions.map((opt, i) => opt.isCorrect ? i : -1).filter(i => i !== -1));
                    const userIndices = new Set(sourceAnswers[index] || []);

                    if (correctIndices.size !== userIndices.size) return true;
                    for (const item of userIndices) {
                        if (!correctIndices.has(item)) return true;
                    }
                    return false;
                });
            }

            if (searchTerm) {
                const lowercasedTerm = searchTerm.toLowerCase();
                questionsToDisplay = questionsToDisplay.filter(q => 
                    q.questionText.toLowerCase().includes(lowercasedTerm) ||
                    q.answerOptions.some(opt => opt.answerText.toLowerCase().includes(lowercasedTerm))
                );
            }
            
            setFilteredQuestions(questionsToDisplay);
        }
    }, [showScore, reviewFilter, searchTerm, currentQuizQuestions, userAnswers, reviewingHistoryEntry]);

    useEffect(() => {
        if (!isQuizActive || showScore) return;
        if (timeLeft === 0) {
          calculateFinalScore();
          setShowScore(true);
          setIsQuizActive(false);
          return;
        }
        const timerId = setInterval(() => setTimeLeft(t => t - 1), 1000);
        return () => clearInterval(timerId);
    }, [timeLeft, isQuizActive, showScore, calculateFinalScore]);

    const handleStartQuiz = () => {
        let pool = [...questionPool];
        if (pool.length < QUESTIONS_PER_QUIZ && pool.length > 0) {
        } else if (pool.length === 0) {
            pool = [...masterQuestions.keys()];
        }
        const questionsToTake = Math.min(QUESTIONS_PER_QUIZ, pool.length);
        const shuffledIndices = shuffleArray(pool);
        const quizIndices = shuffledIndices.slice(0, questionsToTake);
        const remainingIndices = shuffledIndices.slice(questionsToTake);
        
        const questionsForQuiz = quizIndices.map(index => masterQuestions[index]);
        setQuestionPool(remainingIndices);
        setupNewQuiz(questionsForQuiz);
    };
    
    const handleAnswerOptionClick = (answerIndex) => {
        const question = currentQuizQuestions[currentQuestion];
        const correctAnswersCount = question.answerOptions.filter(opt => opt.isCorrect).length;
        
        const nextUserAnswers = [...userAnswers];
        let currentAnswers = [...(nextUserAnswers[currentQuestion] || [])];

        if (correctAnswersCount > 1) {
          const answerPosition = currentAnswers.indexOf(answerIndex);
          if (answerPosition > -1) {
            currentAnswers.splice(answerPosition, 1);
          } else {
            currentAnswers.push(answerIndex);
          }
          nextUserAnswers[currentQuestion] = currentAnswers;
        } else {
          nextUserAnswers[currentQuestion] = [answerIndex];
        }
        
        setUserAnswers(nextUserAnswers);
    };

    const handleToggleFlag = () => {
        const newFlags = [...flaggedQuestions];
        newFlags[currentQuestion] = !newFlags[currentQuestion];
        setFlaggedQuestions(newFlags);
    };

    const handleNextOrSubmit = () => {
        const nextQuestion = currentQuestion + 1;
        if (nextQuestion < currentQuizQuestions.length) {
          setCurrentQuestion(nextQuestion);
        } else {
          setShowFinalReviewScreen(true);
        }
    };
      
    const handleSubmitQuiz = () => {
        calculateFinalScore();
        setShowScore(true);
        setShowFinalReviewScreen(false);
    }
      
    const handlePreviousQuestion = () => {
        if (currentQuestion > 0) {
            setCurrentQuestion(currentQuestion - 1);
        }
    }

    const handleRestartQuiz = () => {
        setQuizStarted(false);
        setCurrentQuestion(0);
        setShowScore(false);
        setRawScore(0);
        setScaledScore(0);
        setTimeLeft(QUIZ_DURATION_SECONDS);
        setIsQuizActive(false);
        setFlaggedQuestions([]);
        setSearchTerm('');
        setIsSearchVisible(false);
        setReviewFilter('all');
        setReviewingHistoryEntry(null);
    };
      
    const handleRestartFromHistory = (historyEntry) => {
        setupNewQuiz(historyEntry.questions);
    };

    const handleReviewHistory = (entry) => {
        setReviewingHistoryEntry(entry);
        setIsHistoryVisible(false);
    }
      
    const toggleExplanation = (index) => {
        setExplanationVisibility(prev => ({...prev, [index]: !prev[index]}));
    }
      
    const clearHistory = () => {
        if (window.confirm('Are you sure you want to clear your score history? This action cannot be undone.')) {
            setScoreHistory([]);
            localStorage.removeItem('quizScoreHistory');
        }
    }

    const renderContent = () => {
        if (reviewingHistoryEntry) {
            return <ScoreScreen 
                score={reviewingHistoryEntry.score}
                rawScore={reviewingHistoryEntry.rawScore}
                totalQuestions={reviewingHistoryEntry.totalQuestions}
                questions={reviewingHistoryEntry.questions}
                userAnswers={reviewingHistoryEntry.userAnswers}
                onBackToHome={() => { setReviewingHistoryEntry(null); setIsHistoryVisible(true); }}
                onRestartFromHistory={() => handleRestartFromHistory(reviewingHistoryEntry)}
                reviewFilter={reviewFilter}
                setReviewFilter={setReviewFilter}
                searchTerm={searchTerm}
                setSearchTerm={setSearchTerm}
                isSearchVisible={isSearchVisible}
                setIsSearchVisible={setIsSearchVisible}
                filteredQuestions={filteredQuestions}
                explanationVisibility={explanationVisibility}
                toggleExplanation={toggleExplanation}
                isReviewVisible={isReviewVisible}
                setIsReviewVisible={setIsReviewVisible}
            />;
        }
        if (!quizStarted) return <LandingPage onStart={handleStartQuiz} onShowHistory={() => setIsHistoryVisible(true)} />;
        if (showScore) return <ScoreScreen 
            score={scaledScore}
            rawScore={rawScore}
            totalQuestions={currentQuizQuestions.length}
            questions={currentQuizQuestions}
            userAnswers={userAnswers}
            onRestart={handleRestartQuiz}
            onShowHistory={() => setIsHistoryVisible(true)}
            reviewFilter={reviewFilter}
            setReviewFilter={setReviewFilter}
            searchTerm={searchTerm}
            setSearchTerm={setSearchTerm}
            isSearchVisible={isSearchVisible}
            setIsSearchVisible={setIsSearchVisible}
            filteredQuestions={filteredQuestions}
            explanationVisibility={explanationVisibility}
            toggleExplanation={toggleExplanation}
            questionPoolLength={questionPool.length}
            isReviewVisible={isReviewVisible}
            setIsReviewVisible={setIsReviewVisible}
        />;
        if (showFinalReviewScreen) {
            const flagged = [];
            const unanswered = [];
            currentQuizQuestions.forEach((_, index) => {
                if (flaggedQuestions[index]) {
                    flagged.push(index);
                }
                if (!userAnswers[index] || userAnswers[index].length === 0) {
                    unanswered.push(index);
                }
            });
            return <FinalReviewScreen
                flaggedQuestions={flagged}
                unansweredQuestions={unanswered}
                onGoToQuestion={(qIndex) => {
                    setCurrentQuestion(qIndex);
                    setShowFinalReviewScreen(false);
                }}
                onSubmitFinal={handleSubmitQuiz}
            />;
        }
        return <QuestionView 
            currentQuestionData={currentQuizQuestions[currentQuestion]}
            currentQuestionIndex={currentQuestion}
            totalQuestions={currentQuizQuestions.length}
            userAnswers={userAnswers}
            onAnswer={handleAnswerOptionClick}
            onFlag={handleToggleFlag}
            onNext={handleNextOrSubmit}
            onPrev={handlePreviousQuestion}
            onSubmit={handleSubmitQuiz}
            flaggedQuestions={flaggedQuestions}
            timeLeft={timeLeft}
            setCurrentQuestion={setCurrentQuestion}
        />;
    }

    return (
        <div className="min-h-screen bg-gray-100 flex items-center justify-center p-0 md:p-4 font-sans">
          <div className="w-full h-full md:max-w-6xl md:h-auto bg-white md:rounded-lg shadow-2xl md:p-8 transform transition-all duration-300">
            <div className="p-4 md:p-0">
              {renderContent()}
            </div>
          </div>
          {/* Score History Panel */}
          <div className={`fixed inset-0 z-50 transition-all duration-500 ease-in-out ${isHistoryVisible ? '' : 'pointer-events-none'}`}>
            <div 
                className={`absolute inset-0 bg-black transition-opacity duration-500 ${isHistoryVisible ? 'bg-opacity-50' : 'bg-opacity-0'}`}
                onClick={() => setIsHistoryVisible(false)}
            ></div>
            <div className={`absolute top-0 right-0 h-full w-full max-w-md bg-white shadow-2xl transform transition-transform duration-500 ease-in-out ${isHistoryVisible ? 'translate-x-0' : 'translate-x-full'}`}>
                <div className="p-6 flex flex-col h-full">
                    <div className="flex justify-between items-center border-b pb-4 mb-4">
                        <h2 className="text-2xl font-bold text-gray-800">Score History</h2>
                        <button onClick={() => setIsHistoryVisible(false)} className="p-2 rounded-full hover:bg-gray-200">
                            <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                            </svg>
                        </button>
                    </div>
                    <div className="flex-grow overflow-y-auto">
                        {scoreHistory.length > 0 ? (
                            <ul className="space-y-4">
                                {scoreHistory.map((entry) => (
                                    <li key={entry.id}>
                                        <button onClick={() => handleReviewHistory(entry)} className={`w-full p-4 rounded-lg flex justify-between items-center text-left ${entry.score >= PASSING_SCORE ? 'bg-green-100 hover:bg-green-200' : 'bg-red-100 hover:bg-red-200'}`}>
                                            <div className="flex-grow">
                                                <p className="font-bold text-lg">{entry.score >= PASSING_SCORE ? 'Pass' : 'Fail'}</p>
                                                <p className="text-sm font-semibold text-gray-700">{Math.round(entry.rawScore)} / {entry.totalQuestions} correct</p>
                                                <p className="text-xs text-gray-500 mt-1">{entry.date}</p>
                                            </div>
                                            <p className="text-3xl font-bold">{entry.score}</p>
                                        </button>
                                    </li>
                                ))}
                            </ul>
                        ) : (
                            <p className="text-center text-gray-500 mt-8">No scores recorded yet.</p>
                        )}
                    </div>
                    {scoreHistory.length > 0 && (
                        <div className="border-t pt-4 mt-4">
                            <button onClick={clearHistory} className="w-full bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-lg">
                                Clear History
                            </button>
                        </div>
                    )}
                </div>
            </div>
          </div>
        </div>
    );
};

export default App;

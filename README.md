# Understanding-Log-Sources-Investigating-with-Splunk
<img width="1024" height="541" alt="image" src="https://github.com/user-attachments/assets/1b9c30cd-dc74-4da4-9c61-54a526327dac" />
Project Description:
I recently completed an intensive Hack the Box module focused on Splunk, a leading platform in the realm of cybersecurity analytics and threat detection. This project provided me with a deep dive into Splunk's architecture, components, and core functionalities, equipping me with a robust understanding of its capabilities. I did an entire write up on this project in the Github link above.

Overview:
A major focus was on crafting effective detection-related SPL (Search Processing Language) searches, which are essential for Splunk's querying capabilities. Through practical exercises and tutorials, I gained proficiency in creating targeted searches to identify security incidents, anomalies, and potential threats.
To reinforce the practical application of Splunk as a Security Information and Event Management (SIEM) tool, the module presented real-world scenarios. These scenarios allowed me to act as a security analyst, investigating simulated security incidents using Splunk. This hands-on experience helped me navigate through large volumes of machine data, leverage Splunk's search capabilities, and apply various data analysis techniques.
Additionally, the module covered the creation of TTP-driven and analytics-driven SPL searches. TTP-driven searches involved crafting queries aligned with known Tactics, Techniques, and Procedures used by threat actors, enabling proactive detection and response to sophisticated attacks. Analytics-driven searches leveraged statistical analysis and mathematical models to identify abnormal behaviors and anomalies indicative of potential security breaches.
Throughout the module, I gained valuable insights into using Splunk as a robust security monitoring and incident investigation tool. I developed the skills needed to identify and understand ingested data and available fields within Splunk.

Key Learning Objectives:
Understanding Splunk's architecture, components, and core functionalities.
Proficiency in crafting effective detection-related SPL searches.
Practical application of Splunk as a SIEM tool in investigating security incidents.
Creation of TTP-driven and analytics-driven SPL searches.
Skills in using Splunk for security monitoring and incident investigation.

Hands-On Practice:
The module included sections with hands-on exercises to practice the techniques covered. It concluded with a practical skills assessment to gauge understanding. Learners could reproduce detection examples provided in the interactive sections or their virtual machines.

Module Details:
Classification: Hard
Prerequisites: Basic knowledge of Windows event logs and common attack principles
Duration: Self-paced, start and stop anytime
Assessment: Completion of all exercises and skills assessment required for marking the module as complete

Exploring Splunk and SPL
This section focuses on utilizing Splunk's SIEM capabilities and exploring its various data analysis tools using the Splunk Processing Language (SPL).

Splunk as a SIEM
To begin with basic SPL commands, I set up a VM host with a Splunk Index named main, containing Windows Security, Sysmon, and other logs.

Starting with a simple query, I searched the index for the term "UNKNOWN" using index=main "UNKNOWN":

<img width="956" height="742" alt="image" src="https://github.com/user-attachments/assets/452c5e45-31f8-45fc-bf8f-b05f16c310db" />

Next, I modified the query to include wildcards and find all occurrences of "UNKNOWN" with any number of characters before and after it:

<img width="960" height="278" alt="image" src="https://github.com/user-attachments/assets/ff944a54-2718-4f89-8e51-5358cf9800aa" />

The use of wildcards expanded the search results as the criteria became less strict.

Splunk automatically identifies data fields from the events such as source, sourcetype, host, and EventCode. For example, from the previous search, I could see some of the hosts that were found:

<img width="880" height="379" alt="image" src="https://github.com/user-attachments/assets/7957cf38-1505-4850-9ff5-17f35e284842" />


I then created queries using these data fields combined with comparison operators to filter based on the values found for each data field. For instance, I searched for all records where the host is "waldo-virtual-machine" using index="main" host="waldo-virtual-machine":

<img width="953" height="537" alt="image" src="https://github.com/user-attachments/assets/4ee89ea0-02b4-4286-b144-bbb22546d78a" />

Using a pipe | I directed the output of a search into a command, similar to Linux. For manipulating data fields, SPL offers a fields command that can be used to remove and add filters from the results.

With the fields command, I conducted a search on all Sysmon events with EventCode 1 but removed the "User" field from the results. This filtered out all the results where the user initiated the process:

<img width="958" height="555" alt="image" src="https://github.com/user-attachments/assets/6d08599b-3cb4-4b39-b83c-d7bfe3c6c941" />


Another useful command is table which can be used to change the display of the results into a table with the desired columns.

With the Sysmon EventCode 1 results, I created a table that only displayed the time, host, and image fields:

<img width="956" height="424" alt="image" src="https://github.com/user-attachments/assets/253c946b-8b1e-4b1d-9beb-ad3ded3a558f" />


If I wanted to use a different name for a field, I could use the rename command to change it in the results. For example, I changed the Image field to be "Process":

<img width="496" height="61" alt="image" src="https://github.com/user-attachments/assets/35ce81ed-5a9c-4700-bac8-a60c4c460422" />

<img width="891" height="593" alt="image" src="https://github.com/user-attachments/assets/e91dd040-166a-41fe-a7af-193d6d75336d" />


Another helpful command is dedup which deletes all duplicate events based on a specified field. In the previous results where I renamed Image to be Process, each value had many counts, but many of them were filtered out with dedup:

<img width="600" height="674" alt="image" src="https://github.com/user-attachments/assets/54c52e73-598f-445d-8962-1277f4cf5ddf" />


Using the sort command, results can sorted in ascending or descending order based on a specified field. Here, I sorted the results by the time they occurred and in descending order to see the most recent results:

<img width="951" height="721" alt="image" src="https://github.com/user-attachments/assets/20853655-8887-4f2b-93f0-98c665c47456" />


The stats command allows the user to compute statistical operations towards the results for organization purposes. Using the count operation, I compiled the results to show the number of times that each Image created an event at a certain time:

<img width="948" height="450" alt="image" src="https://github.com/user-attachments/assets/6f529005-8539-44b9-b221-c35b2d1297ac" />


To further expand on the data visualization aspect of SPL, there is the chart command that is very similar to stats but outputs the results into a table-like data visualization.

I created a chart with the previous example of taking the count of events that an Image created at a specific time:

<img width="957" height="601" alt="image" src="https://github.com/user-attachments/assets/43bc2a7a-d3fb-4dcf-82ea-404e74359d54" />


If I needed to further redefine or create a new field from an existing field, I could use the eval command. For example, if I wanted the output of the Image field but in all lowercase, I could create a new field and set its results to the lowercase version of Image.

eval Process_Path=lower(Image) would create a new field called "Process_Path" and uses the lowercase function with the Image field as input to set the new field equal to the lowercase results of the Image field:

<img width="603" height="572" alt="image" src="https://github.com/user-attachments/assets/18687d1e-e11b-42d5-8a8c-e6752b58a80d" />


I could also extract new fields from existing ones using regular expressions through the rex command.

[^%](?<guid>{.*}) is a regular expression that:

Excludes anything that starts with %
Creates a named capture group called "guid" that assigns the name to anything in between curly braces and isn't a new line character
This would create a new field called "guid" that I could then use in further commands. Using the new field, I would create a table that shows all the extracted data:

<img width="949" height="623" alt="image" src="https://github.com/user-attachments/assets/cd494dcc-0c5a-4bbe-9a8a-577afbab449a" />


Splunk Lookups can add to the results of a query by matching fields in the results to fields in lookup files.

I created a file called malware_lookup.csv that holds fields matching files to whether or not they are malware. This acted as a lookup table file that I could use with the data to do a lookup on known malicious files.

<img width="743" height="190" alt="image" src="https://github.com/user-attachments/assets/72f73bd0-b997-4c67-b831-209f1a689aa2" />


After adding malware_lookup.csv to the Lookup files in Splunk's settings, I was ready to use it with the lookup command.

First, I did some results manipulation by extracting all the names of the files listed in the Image field, converting them to lowercase, and then storing the results into a new field called "filename":

| rex field=Image "(?P<filename>[^\\\]+)$" = extract new filename field | eval filename=lower(filename) = converts all of the results for the filename field to lower case

Now, I could compare the values of the new filename field to the malware_lookup.csv (which has a matching filename column) to see if any of the found files are known malware.

| lookup malware_lookup.csv filename OUTPUTNEW is_malware = uses the newly created filename Splunk field as a key to lookup the column filename in malware_lookup.csv and then outputs the corresponding "is_malware" value into a new Splunk field with the same name

With these commands, I had extracted all the filenames found in the Splunk Image field and compared them against a list of known malicious files to see which ones were found in my data:

<img width="955" height="425" alt="image" src="https://github.com/user-attachments/assets/40e4f361-f89e-483a-9ad0-4b68ed03586f" />


There is an alternate way I could have done, a command which replaces the rex with mvdedup and mvindex to split the full file paths by backslashes and take the last index, which is the filename.

eval filename=mvdedup(split(Image, "\\")) = split up the file names from the Image field using the backslashes and remove any duplicates

eval filename=mvindex(filename, -1) = select the last index which will be the filename

The rest is similar to the rex version minus the duplicates, and the results are the same:

<img width="968" height="526" alt="image" src="https://github.com/user-attachments/assets/89feeb9f-932a-4477-8322-83285bee7524" />


Transactions in Splunk are used to group events that share common characteristics. With the transaction command, I can group events based on certain fields like Image.

| transaction Image startswith=eval(EventCode=1) endswith=eval(EventCode=3) maxspan=1m = creates a transaction of events within 1 minute of each other that start with an event with EventCode 1 and ends with an event with EventCode 3

After removing the duplicate values, I can identify programs that all created certain types of events within 1 minute of each other:

<img width="951" height="591" alt="image" src="https://github.com/user-attachments/assets/a80a6ab6-daa2-4915-a10e-7042f049bf72" />


Finally, I use SPL's capability to do subsearches to filter out large sets of data. I start by creating a very simple search to get all Sysmon events with EventCode 1.

Using the logical NOT keyword, I can filter out all the results of a subsearch from the results of this main search:

NOT
	[ search index="main" sourcetype="WinEventLog:Sysmon" EventCode=1
	| top limit=100 Image
	| fields Image ]
The subsearch identifies all Sysmon events with Event Code 1 and returns the 100 most common values of the Image field. Consequently, these results are excluded from the main search:

<img width="972" height="726" alt="image" src="https://github.com/user-attachments/assets/f4b0da47-7a7b-45e9-b905-9b1d9792abb5" />


Filtering out these events provides insight into some of the Event Code 1 events that showcase more rare and unique instances of programs being used.

Identify Available Data
To gain an overview of all the indexes in my dataset, I utilize the eventcount command with summarize=false to generate a table of each one: 
<img width="959" height="350" alt="image" src="https://github.com/user-attachments/assets/fc5dc669-0eca-4bb2-b5aa-379812ff6507" />


Next, I employ the metadata command to examine all the different sourcetype objects (i.e Sysmon) that have generated events in my data:

<img width="947" height="414" alt="image" src="https://github.com/user-attachments/assets/8630cc2a-8fe1-4c22-89da-eba134f94e80" />


Similar commands can be used to view all the hosts and gather information about the sources:

<img width="950" height="436" alt="image" src="https://github.com/user-attachments/assets/887b5ef5-ab57-40b4-aef8-3b5fe140e45b" />


<img width="949" height="604" alt="image" src="https://github.com/user-attachments/assets/66c2f1a0-cec2-49c4-9c32-1e39c9b7ec5b" />


Once I have identified the different sourcetypes, I can view their raw event data in a table using table _raw:

<img width="483" height="675" alt="image" src="https://github.com/user-attachments/assets/3d4c3216-832e-482d-8a39-401eebe50847" />


For information about the types of fields a sourcetype has, I utilize the fieldsummary command:

<img width="953" height="615" alt="image" src="https://github.com/user-attachments/assets/dd29f8e9-2cf9-4eff-94d2-29e66219dbff" />


Further filtering of the results can be done based on some of the returned statistics from fieldsummary:

<img width="960" height="526" alt="image" src="https://github.com/user-attachments/assets/e5a4d266-a4eb-4f2a-acab-7c6a98d05efd" />


For time-based queries, the bucket command can group events together, and then computing statistics on them makes it easy to view summaries of defined time periods. In this query, all events are bucketed into singular days, and the counts of each sourcetype in each index are computed:

<img width="967" height="590" alt="image" src="https://github.com/user-attachments/assets/7dd5fc8e-9399-4ed3-b0d7-2f5b112eafb8" />


Another method to find uncommon events is with the rare command. Here, the top 10 least common combinations of index and sourcetype are retrieved:

<img width="965" height="434" alt="image" src="https://github.com/user-attachments/assets/76b0c1f1-9e8c-4cd9-af42-3a701cc87526" />


The sistats command can also be used to explore event diversity and extract information about common/uncommon events. This command counts the number of events based on index, sourcetype, source, and host to provide a big picture analysis of the events:

<img width="972" height="672" alt="image" src="https://github.com/user-attachments/assets/5c428389-da9b-4dde-936d-9eedf4aebe30" />


Practice Queries
Find the account name with the highest amount of Kerberos authentication ticket requests
Given that the specific Event Code for Kerberos authentication ticket requests is unknown, I initially perform a simple search for "kerberos authentication" to identify it as 4768:

<img width="1004" height="558" alt="image" src="https://github.com/user-attachments/assets/64021f92-c01d-4f26-8c64-da24f91ea6d1" />

Subsequently, I execute a search on Event Code 4768 that counts all the Account_Name field values, places them into a table, and sorts them to determine the account with the highest count:

<img width="951" height="483" alt="image" src="https://github.com/user-attachments/assets/b54e1da8-6483-4fa7-8c67-be6afd98bbfe" />


The account named "waldo" has the highest number of Kerberos authentication requests.

Find the number of distinct computers accessed by the account name SYSTEM in all Event Code 4624 events
For this more specific query, I instantly retrieve the information by selecting all events with Event Code 4624 and the Account_Name SYSTEM, then utilizing dedup to obtain all the unique ComputerName values:

<img width="1027" height="617" alt="image" src="https://github.com/user-attachments/assets/31f13a30-ed77-41d9-bb44-917031c1b709" />


This query returns 10 results, indicating that the SYSTEM account accessed 10 unique computers in the 4624 events.

Splunk Applications - Sysmon
To showcase the practicality and functionality of Splunk applications, I'll be utilizing the Sysmon App for Splunk.

After downloading the app into my Splunk Enterprise instance, I can confirm its functionality and access all its tools from the toolbar:

<img width="945" height="126" alt="image" src="https://github.com/user-attachments/assets/c22a1c29-9d7a-460c-821c-bea6ffd6a70a" />


Within the File Activity section, I can examine all the files created within my dataset:

<img width="937" height="703" alt="image" src="https://github.com/user-attachments/assets/ee725ca6-1b6c-47ca-90ec-773bd7d71c32" />


However, the "Top Systems" section does not display any data because the default search used by the app is not compatible with my dataset:

<img width="934" height="304" alt="image" src="https://github.com/user-attachments/assets/e10b505c-87df-4cc7-936d-4579a88b629b" />


To address this, I manually edit the search within the UI to align it with my data, ensuring it functions as a standard Splunk search would.

The original search was sysmon EventCode=11 | top Computer, but since my data does not contain a field named "Computer," I modify it to "ComputerName" to accurately reflect my dataset:

<img width="803" height="462" alt="image" src="https://github.com/user-attachments/assets/62390446-c4c2-4ff6-98e8-7ae7caa9a700" />


As a result, the "Top Systems" section now displays accurate data because the underlying search produces results:

<img width="942" height="420" alt="image" src="https://github.com/user-attachments/assets/476c20a8-90d8-43bd-ad65-8840b60e3652" />


Instances like the above example highlight that downloaded apps may not always perfectly align with your dataset in terms of keywords and fields. I proceeded to make additional adjustments to some of the searches used by the Sysmon App for Splunk.

For example, the app included a report to showcase the number of network connections made by an application. However, many of the fields and search terms used were incompatible with my dataset:

<img width="800" height="496" alt="image" src="https://github.com/user-attachments/assets/f87ccdf2-d239-4036-95e3-155e8ce71da9" />


To enhance the functionality of this search, I modified it to accurately display the number of network connections made by the SharpHound.exe application.

While there were several fields to edit, such as protocol, dest_port, dest_host, and dest_ip, I successfully identified that the SharpHound app had made 6 network connections:

<img width="948" height="336" alt="image" src="https://github.com/user-attachments/assets/6331c3a6-3a30-460d-a373-273dd1d9b20c" />


Intrusion Detection With Splunk
This section will delve into real-world intrusion detection scenarios, simulating the techniques that blue teams use to hunt for attacks within an organization. I'll employ common techniques to identify various types of attacks present in the dataset, which contains over 500,000 events.

Search Performance Optimization
To start, I'll focus on identifying attacks in the Sysmon data. First, I'll use a simple command to determine the number of events for Sysmon:

<img width="1001" height="545" alt="image" src="https://github.com/user-attachments/assets/944c0d5a-667b-4ec8-afa3-eb95e24e5aa9" />


Next, I'll compare the performance differences between SPL searches by searching for the system name "uniwaldo.local" with and without wildcards:

<img width="965" height="226" alt="image" src="https://github.com/user-attachments/assets/ed53ad77-f3f3-415a-829e-8b63452d68ac" />
<img width="954" height="239" alt="image" src="https://github.com/user-attachments/assets/2f678dc9-1063-48da-8b85-5ab871dc4aba" />


Although both searches yield the same number of events, the search with wildcards takes significantly longer because it matches many more events.

Another example to improve performance and accuracy is to specify the field when searching, assuming the expected keyword field is known:

<img width="956" height="236" alt="image" src="https://github.com/user-attachments/assets/312608c2-b6ea-4935-a2c9-3258b310d52c" />


Using Attacker Mindset
Sysmon event codes provide insight into the attacks that attackers use against a system or network, as each event code signifies specific processes performed on a host.

I start by examining the number of events related to each Sysmon event code in the data:

<img width="1024" height="690" alt="image" src="https://github.com/user-attachments/assets/39046ccb-0533-4163-892e-59c402f82a3b" />


Event code 1 for process creation can indicate unusual parent-child trees, so I begin searching for attacks using this event code:

<img width="957" height="731" alt="image" src="https://github.com/user-attachments/assets/cf3a8257-6f77-48f4-9eed-b973c2caa1cd" />


Some problematic child processes are cmd.exe and powershell.exe so I look for them in a search with the Image field:

<img width="965" height="709" alt="image" src="https://github.com/user-attachments/assets/555355fa-34ab-4f94-82e3-8cda03df9ad2" />


This narrows down the search to 628 events compared to the initial 5,472.

Some questionable results are where the problematic child processes are spawned from a notepad.exe parent process:

<img width="954" height="76" alt="image" src="https://github.com/user-attachments/assets/47bde3ff-7ec0-486b-a701-06858e4a7ffb" />


I further narrow down the search to focus on these 21 occurrences:

<img width="1029" height="525" alt="image" src="https://github.com/user-attachments/assets/38976e08-bcb9-4a26-8d8b-9457584cd772" />


Examining the first event reveals a command-line prompt where PowerShell is used to download a file from a server:

<img width="534" height="155" alt="image" src="https://github.com/user-attachments/assets/02b3843c-1173-4cc2-ad40-98eb92f96b3a" />


Investigating the IP address that the file was downloaded from reveals only two sourcetypes:
<img width="965" height="300" alt="image" src="https://github.com/user-attachments/assets/a2f954d7-b81d-4cc7-bafb-f0873f23c376" />

Specifically examining the syslog sourcetype shows that the IP belongs to the host "waldo-virtual-machine" and it is using its ens160 interface:

<img width="941" height="613" alt="image" src="https://github.com/user-attachments/assets/3e3d610e-6328-4e59-9a8f-8b66e2487196" />

One event shows that a new address record has been created on the interface to establish some form of communication with a Linux system:

<img width="696" height="106" alt="image" src="https://github.com/user-attachments/assets/948dfb5c-deaa-4db5-9648-4d88389842ca" />


I also checked the Sysmon-related logs with the CommandLine field to investigate further:

<img width="953" height="570" alt="image" src="https://github.com/user-attachments/assets/25a8e6c0-13f2-4dc4-b35c-d273be94c38b" />

These results show many commands being used to download likely malicious files, confirming that the Linux system being connected to is likely infected.

Adding the count for the host field reveals that two hosts were victims of the attack:

<img width="988" height="592" alt="image" src="https://github.com/user-attachments/assets/1d7923f8-9498-436c-9fbf-0f198a3ae8b9" />


Based on the file name, it appears that one of the hosts was targeted with a DCSync attack using a PowerShell file:

<img width="942" height="51" alt="image" src="https://github.com/user-attachments/assets/8bb435ec-bffa-4811-9dc5-7812aa8b8cff" />


This type of attack is related to Active Directory, and I can focus on this by examining events with event code 4662. I also used a couple of specifiers to show the procedures that a DCSync attack uses:

AccessMask=0x100 = this will appear when Control Access is requested which is needed for a DCSync attack because it requires high-level permissions

AccountName!=*$ = removes all results where the account being used is a service, so I only see instances where a user account was used for DCSync which is normally not allowed

<img width="970" height="702" alt="image" src="https://github.com/user-attachments/assets/46992e2e-c753-4098-a197-dc071d9fa23a" />


Examining the two returned events, I see two GUIDs:

<img width="418" height="182" alt="image" src="https://github.com/user-attachments/assets/de0b8d0a-ce07-43dd-a1fd-f4b5e79faa50" />


The first is for "DS-replication-Get-Changes-All":

<img width="641" height="404" alt="image" src="https://github.com/user-attachments/assets/f3e6bcbe-4fbb-4063-a0e3-9427c32f807d" />


From the documentation, I see that this function is used to "replicate changes from a given NC," essentially defining a DCSync attack as it attempts to ask other domain controllers to replicate information and gain user credentials.

This information concludes that the attacker has infiltrated a system, gained domain admin rights, moved laterally across the network, and exfiltrated domain credentials for the network.

I now know that the waldo user was used to execute this attack and that the account likely has domain admin rights itself, but I am not yet aware of how the attacker gained these rights initially.

Knowing that lsass dumping is a prevalent credential harvesting technique, I conduct a search to see the types of programs related to event code 10 and the keyword "lsass":

<img width="985" height="510" alt="image" src="https://github.com/user-attachments/assets/28e8b5e4-5c2e-471b-a292-a3af662a5545" />


Assuming lower event counts can be considered out of the ordinary, or not typical behavior, I find that some of the lowest event counts are related to notepad.exe and rundll32:

<img width="1006" height="78" alt="image" src="https://github.com/user-attachments/assets/d1530c03-3ad4-414b-832b-7bc0f7b76290" />


Further inspection of notepad reveals only one event that Sysmon thinks is related to lsass and credential dumping:

<img width="942" height="434" alt="image" src="https://github.com/user-attachments/assets/c4340bbf-aef8-47dd-a636-9d9da04f61c9" />
<img width="604" height="451" alt="image" src="https://github.com/user-attachments/assets/f407a292-b30c-4898-891b-d1dac0fdd6b3" />


Meaningful Alerts
In the previous section, I found that APIs were called from UNKNOWN memory regions, which eventually led to the DCSync attack I investigated. I can now create an alert to detect this behavior and potentially prevent similar attacks in the future.

First, I want to know more about the UNKNOWN memory location usage, so I search to see the related event codes:

<img width="946" height="274" alt="image" src="https://github.com/user-attachments/assets/7f639de6-bc07-48a8-982f-1a80e33a6092" />


The results show that the only related event code is 10, which is for process access. Therefore, I am looking for events that attempt to open handles to other processes that don't have a memory location mapped to the disk.

<img width="992" height="721" alt="image" src="https://github.com/user-attachments/assets/931cd12b-3abc-494e-ae3e-2dee5d111d44" />


Filtering out many normal instances, I start by removing any events where the source program tries to access itself, as the attack I investigated did not do this:

<img width="956" height="730" alt="image" src="https://github.com/user-attachments/assets/0e71f005-65f0-47e5-ad7d-c72cbc1535fb" />


To further filter the programs, I exclude anything C# related by excluding any .NET, ni.dll, or clr.dll references:

<img width="1015" height="556" alt="image" src="https://github.com/user-attachments/assets/a73fa6bc-f879-4fcd-86fc-b0e7ee455051" />


Another instance to remove is anything related to WOW64, which has a non-harmful phenomenon that comprises regions of memory that are unknown:

<img width="992" height="486" alt="image" src="https://github.com/user-attachments/assets/6f6799ac-d0c5-4a09-b3ff-c3dd4e5c440a" />


Explicitly removing anything related to explorer, which produces many non-malicious events, through the SourceImage field:

<img width="956" height="419" alt="image" src="https://github.com/user-attachments/assets/bb34238f-08a2-477e-ab71-c7dbf015a725" />


Now, I have a list of only 4 programs that exhibit the behavior I'm trying to target with my alert. I could then analyze and possibly filter out more non-threatening programs, but for now, this is an alert that could work to prevent the domain admin credential harvesting I identified earlier.

This alert has some issues, as the dataset includes very few false positives and is tailored specifically for this exercise. For example, the alert could be bypassed by simply using an arbitrary load of one of the DLLs that I excluded. However, for the purposes of this exercise, I was able to identify an attack pattern and create a targeted alert that would detect it.

Further Detection Practice
Find the other process that dumped credentials with lsass
To find the other process, I go back to my finalized alert for the attack and look at some of the TargetImages:

<img width="982" height="562" alt="image" src="https://github.com/user-attachments/assets/bd635384-6e4c-4e0e-bc74-c9dc00ff4b01" />


From there, I can see that, in addition to notepad.exe, rundll32.exe was also using lsass for credential dumping:

<img width="967" height="84" alt="image" src="https://github.com/user-attachments/assets/5b6e2944-032d-419c-aceb-f795401637e6" />


Find the method rundll32.exe dumped lsass
To find the method, I create a target search to see all the events that have the source program as rundll32.exe and the target program as lsass:

<img width="992" height="554" alt="image" src="https://github.com/user-attachments/assets/eacf9f8d-966c-4314-9041-81c5223e6116" />


From the search, I extract the unique call traces and find many DLLs being used. After a little research, I find that one of the DLLs, comsvcs.dll, is a common dumping DLL.

Find any suspicious loads of clr.dll that could be C sharp injection/execute-assembly attacks, then find the suspicious process that was used to temporarily execute code
To find suspicious loads of clr.dll, I start by getting an idea of all the types of events that include the phrase clr.dll. After some searching, I find that an important field to pay attention to is what processes were loading the clr.dll image:

<img width="949" height="683" alt="image" src="https://github.com/user-attachments/assets/688aba33-e0c7-4213-80b6-a99265bbc7ba" />


One way that I began to filter the results was to just see which images Sysmon correlated with process injection attacks:

<img width="942" height="689" alt="image" src="https://github.com/user-attachments/assets/588c939e-8a9a-44d0-a95c-399328a14c85" />


Filtering out normal instances, I remove any events related to Microsoft processes like Visual Studio:

<img width="964" height="599" alt="image" src="https://github.com/user-attachments/assets/4ffc7e65-1ef5-40bc-ad16-eefe55cd2105" />


Unsurprisingly, I find that both notepad.exe and rundll32.exe, from my original DCSync alert, were also used to execute code.

Find the two IP addresses of the C2 callback server
This is as simple as looking for any IPs that rundll32.exe or notepad.exe were connected to:

<img width="953" height="307" alt="image" src="https://github.com/user-attachments/assets/2368c622-4aaa-4c76-bc86-ef819f32a825" />
<img width="981" height="381" alt="image" src="https://github.com/user-attachments/assets/2ec841d3-da3b-456c-9f51-b1357754db8c" />


10.0.0.186 and 10.0.0.91 appear to be the command and control servers.

Find the port that one of the two C2 server IPs used to connect to one of the compromised machines
I started with a broad search to see any mention of the two IP addresses:

<img width="948" height="497" alt="image" src="https://github.com/user-attachments/assets/b826750a-07e7-4829-9c68-17461e86b508" />


Since in this case I only care about network connections, I filter to see all events with event code 3:

<img width="956" height="558" alt="image" src="https://github.com/user-attachments/assets/65c00a85-763b-4478-a2b0-17450408e3a9" />


Digging into one of the events gives me an idea of some of the key fields that I want to investigate further:

<img width="243" height="250" alt="image" src="https://github.com/user-attachments/assets/69030b88-927a-4ff7-a3ff-84c681ec0120" />


Since I don't know which of the IPs connected to the compromised machine, I simply extract all the source IPs and their correlating destination ports:

<img width="949" height="333" alt="image" src="https://github.com/user-attachments/assets/b564eaaa-73a2-4e3c-8364-f656b76279f8" />


From these results, I can conclude that the C2 IP 10.0.0.186 used the Remote Desktop Protocol port 3389 to connect to the compromised machines.

Detecting Attacker TTPs
Using attacker TTPs to create searches and alerts involves searching for known behavior and abnormal behavior. This section covers creating searches based on attacker behavior.

Crafting SPL Searches Based on Known TTPs
Attackers often use Windows binaries like net.exe for reconnaissance activities to find privilege escalation and lateral movement opportunities. To target this behavior, I use Sysmon event code 1 and look for command-line usage that can provide information on a host or network:

<img width="959" height="715" alt="image" src="https://github.com/user-attachments/assets/076e452c-d166-409a-9ec1-3385df6b3778" />


Searching for malicious payload requests can be done by looking for requests for common whitelisted sites that attackers use to host their payloads, like githubusercontent.com. Sysmon event 22 for DNS queries can help me identify these occurrences.

There is a QueryName field that I can use to search for githubusercontent.com requests:

<img width="600" height="487" alt="image" src="https://github.com/user-attachments/assets/fe5f502b-9537-4bfb-ab7e-0e20b34aa756" />
<img width="941" height="311" alt="image" src="https://github.com/user-attachments/assets/967e18ef-42c5-4f3b-9e52-bcbe529e0eec" />


Several MITRE ATT&CK techniques use PsExec and its high-level permissions to conduct attacks. Some common Sysmon event codes that relate to these attacks are 13, 11, 17, and 18.

Leveraging event code 13, which is for registry value sets, takes a lot of involvement. However, using some resources like Splunking with Sysmon can provide some well crafted searches:

<img width="957" height="726" alt="image" src="https://github.com/user-attachments/assets/cdda67c7-b5ee-431c-a251-87dd1da30dc8" />


index="main" sourcetype="WinEventLog:Sysmon" EventCode=13 Image="C:\\Windows\\system32\\services.exe" TargetObject="HKLM\\System\\CurrentControlSet\\Services\\*\\ImagePath" = this will isolate to event code 13, select the services.exe image which handles service creation, and grabs the TargetObject which are the registry keys that will be affected

rex field=Details "(?<reg_file_name>[^\\\]+)$" = grabs the file name from the Details field and stores it in a new field reg_file_name

eval reg_file_name = lower(reg_file_name), file_name = if(isnull(file_name), reg_file_name, lower(file_name)) = this converts reg_file_name to lower case, then modifies the file_name field so that if it is null it will be filled with reg_file_name and if not it keeps its original value and sets it to lower case as well

stats values(Image) AS Image, values(Details) AS RegistryDetails, values(\_time) AS EventTimes, count by file_name, ComputerName = for each unique combination of file_name and Computer name, this will extract all the unique values of Image, Details, TargetObject, and time

This query will be able to tell me all the instances where services.exe modified the ImagePath value of a service. In the search results, I have extracted the details of these modifications.

Using Sysmon event code 11 for file creation shows that there have been executions resembling PsExec:

<img width="971" height="384" alt="image" src="https://github.com/user-attachments/assets/64c28670-0f11-45b7-8b4d-f407738fe58d" />

Sysmon event code 18 for pipe connections can also show a PsExec execution pattern:

Archive or zipped files are typically used for data exfiltration, so using event code 11, I can filter for these types of file creations and see some concerning results:

<img width="967" height="724" alt="image" src="https://github.com/user-attachments/assets/77f4b921-d1e1-4e16-b23c-5723e28f9614" />


A common way to actually download the payloads that attackers are hosting is through PowerShell or MS Edge while also targeting Zone.Identifier, which signals files downloaded from the internet or untrustworthy sources:

<img width="967" height="734" alt="image" src="https://github.com/user-attachments/assets/fab50239-761f-442d-af39-87db8b01b4e9" />
<img width="977" height="530" alt="image" src="https://github.com/user-attachments/assets/71e49c72-9e4e-4f74-a665-275b51af9180" />


Detecting execution from unusual places, for example, in this search, I look for process creations in the downloads folder using event code 1:

<img width="1004" height="492" alt="image" src="https://github.com/user-attachments/assets/749658d9-3930-4157-abe3-bae64a989b73" />


Another sign of malicious activity is the creation of DLL and executable files outside of the Windows directory:

<img width="1036" height="651" alt="image" src="https://github.com/user-attachments/assets/c0418ace-e3df-4166-b061-a583755d75de" />


Even though it takes a bit of manual involvement, another attribute to look for is the misspelling of common programs. In this case, I look for a misspelling of the PsExec files:

<img width="952" height="741" alt="image" src="https://github.com/user-attachments/assets/1e0033e1-ce3d-434d-8952-8025117f52b6" />


Finally, one of the most common tactics is using non-standard ports for communications and data transfers. Searching for this can be as simple as looking for all network connections, event code 3, that aren't using typical ports:

<img width="957" height="710" alt="image" src="https://github.com/user-attachments/assets/5c25a48e-d9ec-481d-b2c4-58f1f09deb81" />


Practice Investigation
Find the password utilized during the PsExec activity
This was very simple to find as the attacker often used command line arguments to enter in the password. I simply looked for any reference to the phrase "password" in Sysmon events and found a PsExec related event with the password stated in the CommandLine field:

<img width="520" height="143" alt="image" src="https://github.com/user-attachments/assets/37ee5757-d020-4e46-bf8c-12ded7cc32a1" />


Detecting Attacker Behavior with Anomaly Detection
Rather than focusing on specific attacker TTPs and crafting searches to target them, another method of detection is by using statistics/analytics to capture abnormal behavior compared to a baseline of "normal" behavior.

Splunk provides many options to do this, including the streamstats command:



Streamstats lets me capture real-time analytics on the data to better identify anomalies that may exist. In the above example:

bin time span=1h = groups the event code 3 events into hourly intervals

streamstats time_window=24h avg(NetworkConnections) as avg stdev(NetworkConnections) as stdev by Image = creates rolling 24-hour averages and standard deviations of the number of network connections for each unique process image

These statistics create the baseline of normal behavior to which I can then extract any events that are outside of the range that I specify with: eval isOutlier=if(NetworkConnections > (avg + (0.5 * stdev)), 1, 0)

SPL Searches Based on Analytics
One of the simpler ways to search for anomalies is by looking for really long commands. Attackers often need to execute complex commands to do their tasks so searching based on the length of the CommandLine field can be effective:



I can also use the same technique of looking for a baseline and apply it to unusual cmd.exe activity:

Splunk96

The above baseline is relatively simple as it looks for average/stdev of the number of commands being run with cmd.exe.

Another anomaly that is often exhibited by malware is a high amount of DLLs being loaded within a short amount of time. This can often be done by non-malicious activity as well, but it is still something to check.

Here I try to filter out as many benign processes that could exhibit this behavior and then extract all of the events where more than 3 unique DLLs are loaded within an hour:

Splunk97

When the same process is executed on the same computer it can often signal malicious or at least abnormal behavior. With Sysmon event code 1 I can see all the events where the same programs are started more than once.

To do this I look for instances where a process, the Image field, has more than one unique process GUID associated with it:

Splunk98

Looking at some of the previously found malicious programs I can see that this behavior was related to some of the lsass dumping activity:

Splunk99

Practice Scenario
Find the source process image that has created an unusually high number of threads in other processes (greater than 2 standard deviations)
To start looking for this process, I first want to know more about the events that I should be looking for. Sysmon event code 8 is for remote thread creation so I check all of these events where the SourceImage field is not the same as the TargetImage:

Splunk100

Then, using a similar search to those I had done previously, I looked for events where the number of threads created exceeded 2 standard deviations:

Splunk101

The steps of this search were to:

Bin the events into 1 hour bins Count the number of threads created based on the source and target images Calculate the average and standard deviation of the number of threads created Find all instances where the number of threads created was greater than 2 standard deviations

This resulted in finding the malicious file randomfile.exe created multiple threads in notepad.exe.

Finding the Source of the Intrusion
Throughout the previous sections I have been investigating different parts of an attack chain that started with domain credentials being dumped which resulted in host infections and data exfiltration. There have been a number of related malicious processes, commands, and DLLS, most notably notepad.exe and rundll32.exe.

In this section I want to learn more about this attack and find its original method of intrusion.

Find the process that created remote threads in rundll32.exe
Finding this process was simple because doing a search on event code 8 events where the target image was rundll32.exe only resulted in one program, randomfile.exe:

Splunk102

Find the process that started the infection
My initial thoughts on how to further investigate the start of the infection was to combine the previous findings about randomfile.exe with the known C2 servers that I found earlier:

Splunk103

Looking into the events that this search provided reminded me of the infected users that could lead to how this infection started:

Splunk104

Since the waldo user has been prevalent throughout this project I decided to look into the types of events that are related to this account and the C2 servers.

Interestingly, I found many events related to Sysmon event code 15 which is related to external downloads from the web:

Splunk105

I wanted to focus on these event code 15 events so I started by first getting an idea of the processes that might be related to these events:

Splunk106

Lots of these programs appear to be malicious based on the prior knowledge of the attack and the only one that I haven't seen before is demon.exe. Luckily this list is very small so I can now begin thinking in terms of a timeline.

I do a simple search to see all of the events related to the waldo user and the C2 servers, but I make sure to see the very first events that have occurred:

Splunk107

From this search I can see that on 10/5/22 the first occurrence of contact with the C2 servers was an event code 15 event categorized as a "Drive-by Compromise" related to the Run.dll file in the user waldo's downloads folder:

Splunk108

A DLL file in the downloads folder itself is suspicious and along with the fact that there is no legitimate DLL named "Run.dll" it's safe to assume this is a malicious file worth investigating.

In this search I also inspected the different target file names and saw some of the usual suspects:

Splunk109

Since the Run.dll events seemed to happen before the demon.dll files, I did a quick search on it:

Splunk110 Splunk111

By looking at the first ever event that occurred with Run.dll I can see that rundll32.exe was used to load it (Sysmon event code 7) only 8 minutes after the Run.dll file was detected as a potential drive-by compromise.

With this knowledge, I can conclude that the waldo user downloaded the malicious file Run.dll which then exploited rundll32.exe to initiate the attack.

Conclusion:
This project was a significant step in my journey to expand my skills and knowledge in cybersecurity, particularly in leveraging Splunk for advanced security operations.

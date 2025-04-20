document.addEventListener("DOMContentLoaded", () => {
    const savedData = JSON.parse(localStorage.getItem("scanResult"));
    console.log(savedData);  // Debugging line to check structure of savedData

    if (savedData) {
        // Scanned URL Logic
        const scannedURL = localStorage.getItem("scannedURL");
        if (scannedURL) {
            console.log("Retrieved URL:", scannedURL);
            const urlElement = document.getElementById("displayScannedURL");
            if (urlElement) {
                urlElement.innerText = scannedURL;
            }
        } else {
            console.log("No URL found in localStorage.");
        }

        // Domain Information
        if (savedData.DomainInformation && savedData.DomainInformation["Domain Information"]) {
            const domainInfo = savedData.DomainInformation["Domain Information"];
            console.log(domainInfo);  // Debugging line for domain info
            
            if (document.getElementById("domainName")) {
                document.getElementById("domainName").innerHTML = domainInfo["Domain Name"];
            }
            if (document.getElementById("registrar")) {
                document.getElementById("registrar").innerHTML = domainInfo["Registrar"];
            }
            if (document.getElementById("creationDate")) {
                document.getElementById("creationDate").innerHTML = domainInfo["Creation Date"];
            }
            if (document.getElementById("expirationDate")) {
                document.getElementById("expirationDate").innerHTML = domainInfo["Expiration Date"];
            }
            if (document.getElementById("domainAge")) {
                document.getElementById("domainAge").innerHTML = domainInfo["Domain_Age"];
            }
            if (document.getElementById("nameServers")) {
                document.getElementById("nameServers").innerHTML = domainInfo["Name Servers"].join(", ");
            }
        }

        // Backlinks Information
        const Data = JSON.parse(localStorage.getItem("backlinkData"));
        console.log(Data);  // Debugging line to check structure of savedData
        if (Data && Data["summary"]) {
            console.log(Data["summary"]); // Debugging line for summary info
        
            if (document.getElementById("Backlinks")) {
                document.getElementById("Backlinks").innerHTML = Data["summary"]["Total Backlinks"];
            }
            if (document.getElementById("Follow_Links")) {
                document.getElementById("Follow_Links").innerHTML = Data["summary"]["Follow Links"];
            }
            if (document.getElementById("NoFollow_Links")) {
                document.getElementById("NoFollow_Links").innerHTML = Data["summary"]["No-Follow Links"];
            }
            if (document.getElementById("Secure_Links")) {
                document.getElementById("Secure_Links").innerHTML = Data["summary"]["Secure Links"];
            }
            if (document.getElementById("NotSecure_Links")) {
                document.getElementById("NotSecure_Links").innerHTML = Data["summary"]["Not Secure Links"];
            }
            if (document.getElementById("Summary")) {
                let learnMoreData = Data["Learn More"]; // Get the array of "Learn More" data
                let formattedLearnMore = ""; // Initialize an empty string
            
                // Loop through each item in the array and format the output
                learnMoreData.forEach((item, index) => {
                    formattedLearnMore += `
                        <div>
                            <strong>Resource ${index + 1}:</strong><br>
                            <strong>Link:</strong> <a href="${item.link}" target="_blank">${item.link}</a><br>
                            <strong>Security Icon:</strong> ${item.security_icon}<br>
                            <hr>
                        </div>
                    `;
                });
            
                // Insert the formatted data into the HTML
                document.getElementById("Summary").innerHTML = formattedLearnMore;
            }
        }
        

        // SSL Information
        if (savedData.SSLinfo && savedData.SSLinfo["SSL Verification"]) {
            const sslInfo = savedData.SSLinfo["SSL Verification"];
            console.log(sslInfo);  // Debugging line for SSL info
            
            if (document.getElementById("IPAddress")) {
                document.getElementById("IPAddress").innerHTML = sslInfo['ip'];
            }
            if (document.getElementById("Valid")) {
                document.getElementById("Valid").innerHTML = sslInfo['IsExpired']=== 0 ? "Not Valid" : "Valid";
            }
            if (document.getElementById("Hosting")) {
                document.getElementById("Hosting").innerHTML = sslInfo['Hosting Location'];
            }
            if (document.getElementById("connectionType")) {
                document.getElementById("connectionType").innerHTML = sslInfo['connection Type'];
            }
            if (document.getElementById("issueDate")) {
                document.getElementById("issueDate").innerHTML = sslInfo['IssueDate'];
            }
            if (document.getElementById("expiryDate")) {
                document.getElementById("expiryDate").innerHTML = sslInfo['expiryDate'];
            }
            if (document.getElementById("issuer")) {
                document.getElementById("issuer").innerHTML = sslInfo['Issuer'];
            }
            if (document.getElementById("domain")) {
                document.getElementById("domain").innerHTML = sslInfo['domain'] ? "Domain Matches SSL Certificate" : "Domain Does Not Match SSL Certificate";
            }
            if (document.getElementById("revocation")) {
                document.getElementById("revocation").innerHTML = sslInfo['Revoked']? "Revoked" : "Not Revoked";
            }
        }

        //Trust score
        if (savedData.Trust) {
            const trustInfo = savedData.Trust;  // Access the Trust object from savedData
            console.log(trustInfo);  // Debugging line to check the Trust information
            
            // Check if the "TrustScore" element exists on the page
            if (document.getElementById("TrustScore")) {
                const trustScore = trustInfo["Trust Score"];  // Get the Trust Score value
                document.getElementById("TrustScore").innerHTML = `Trust Score: ${trustScore}`;
            }
        }
        
        // Vulnerabilities Information
        if (savedData.vulners) {
            const vulnersInfo = savedData.vulners;
            console.log(vulnersInfo);  // Debugging line for vulnerabilities info
            
            if (document.getElementById("vulnerabilityCount")) {
                document.getElementById("vulnerabilityCount").innerHTML = vulnersInfo['Total_Vuls'];
            }
            if (document.getElementById("highCount")) {
                document.getElementById("highCount").innerHTML = vulnersInfo['RiskLevels'][0];
            }
            if (document.getElementById("mediumCount")) {
                document.getElementById("mediumCount").innerHTML = vulnersInfo['RiskLevels'][1];
            }
            if (document.getElementById("lowCount")) {
                document.getElementById("lowCount").innerHTML = vulnersInfo['RiskLevels'][2];
            }
            if (document.getElementById("informationalCount")) {
                document.getElementById("informationalCount").innerHTML = vulnersInfo['RiskLevels'][3];
            }
            if (document.getElementById("Description")) {
                let vulners = vulnersInfo["list_of_vuls"]; // Get the list of vulnerabilities
                let formattedVulnerabilities = ""; // Initialize an empty string
            
                // Loop through each vulnerability and format the output
                vulners.forEach((vul, index) => {
                    formattedVulnerabilities += `
                        <div>
                            <strong>Vulnerability ${index + 1}:</strong><br>
                            <strong>Name:</strong> ${vul.name}<br>
                            <strong>Description:</strong> ${vul.description}<br>
                            <strong>Risk Level:</strong> ${vul.risk_level}<br>
                            <strong>URL:</strong> <a href="${vul.url}" target="_blank">${vul.url}</a><br>
                            <strong>Alert URL:</strong> <a href="${vul.alert_url}" target="_blank">${vul.alert_url}</a><br>
                            <hr>
                        </div>
                    `;
                });
            
                // Insert the formatted vulnerabilities into the HTML
                document.getElementById("Description").innerHTML = formattedVulnerabilities;
            }
            
            if (document.getElementById("Score")) {
                const Score = vulnersInfo["vulScore"];  
                document.getElementById("Score").innerHTML = `vulScore: ${Score}`;
            }
        }


        if (document.getElementById("trustScoreChart")) {
            const trustScoreCtx = document
              .getElementById("trustScoreChart")
              .getContext("2d");
          
            // Check if savedData contains the Trust object
            const savedData = JSON.parse(localStorage.getItem("scanResult"));
            
            
            console.log(savedData);
            
            if (savedData.Trust) {
              const trustInfo = savedData.Trust; // Access the Trust object from savedData
              console.log(trustInfo); // Debugging line to check the Trust information
          
              // Get the Trust Score value
              const trustScore = trustInfo["Trust Score"]; // Ensure Trust Score exists
              const trustworthy = trustScore;
              const risky = 100 - trustworthy; // Calculate the complementary risky value
          
              
              
              
          
              // Check if the "TrustScore" element exists on the page
              if (document.getElementById("TrustScore")) {
                document.getElementById("TrustScore").innerHTML = `Trust Score: ${trustScore}`;
              }
              
          
              // Create the doughnut chart using the dynamically fetched Trust Score
              const trustScoreChart = new Chart(trustScoreCtx, {
                type: "doughnut",
                data: {
                  labels: ["Trustworthy", "Risky"],
                  datasets: [
                    {
                      data: [trustworthy, risky], // Dynamically calculated data
                      backgroundColor: ["#28a745", "#dc3545"], // Green for Trustworthy, Red for Risky
                      borderWidth: 1,
                    },
                  ],
                },
                options: {
                  plugins: {
                    legend: {
                      display: true,
                      position: "bottom",
                    },
                  },
                },
              });
            } else {
              console.error("Trust data is not available in savedData.");
            }
          }
          
          
          // Vulnerability Score Donut Chart
          if (document.getElementById("vulnerabilityScoreChart")) {
            const vulnerabilityScoreCtx = document
              .getElementById("vulnerabilityScoreChart")
              .getContext("2d");

              const savedData = JSON.parse(localStorage.getItem("scanResult"));
              console.log(savedData);
              if (savedData.vulners) {
                const vulInfo = savedData.vulners; // Access the Trust object from savedData
                console.log(vulInfo); // Debugging line to check the Trust information
            
                // Get the Trust Score value
                const Score = vulInfo["vulScore"]; // Ensure Trust Score exists
                const Vul = Score;
                const risky = 100 - Vul; // Calculate the complementary risky value
                console.log(risky);
            
                
                
                
            
                // Check if the "TrustScore" element exists on the page
                if (document.getElementById("Score")) {  
                    document.getElementById("Score").innerHTML = `vulScore: ${Score}`;
                }
                const vulnerabilityScoreChart = new Chart(vulnerabilityScoreCtx, {
              type: "doughnut",
              data: {
                labels: ["Secure", "Vulnerable"],
                datasets: [
                  {
                    data: [Vul, risky], // Example data
                    backgroundColor: ["#007bff", "#ffc107"], // Blue and yellow
                    borderWidth: 1,
                  },
                ],
              },
              options: {
                plugins: {
                  legend: {
                    display: true,
                    position: "bottom",
                  },
                },
              },
            });
          }


    } else {
        alert("No scan results found!");
    }
}
});

// Trust Score Donut Chart

  

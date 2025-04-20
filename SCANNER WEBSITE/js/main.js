


// Header Scroll
let nav = document.querySelector(".navbar");
window.onscroll = function () {
  if (document.documentElement.scrollTop > 20) {
    nav.classList.add("header-scrolled");
  } else {
    nav.classList.remove("header-scrolled");
  }
};
function scanWeb() {
  const urlInput = document.getElementById("websiteURL");

  // Check for validity using the pattern
  if (!urlInput.checkValidity()) {
    alert(urlInput.title); // Show the custom error message from the title attribute
  } else {
    // Redirect only if the URL is valid
    window.location.href = "scan_result.html";
  }
}

function scanWebsite() {
  //const url = document.getElementById("websiteURL").value;
  //window.location.href = "scan_result.html";
  //function scanWebsite() {
  const websiteURL = document.getElementById("websiteURL").value; // Get the URL from input field
  console.log("Initiating full website scan...");
  alert("Starting scan. Please wait...");
  all_scans();
}

function scanningVul() {
  const websiteURL = document.getElementById("websiteURL").value; // Get the URL from input
  fetch("http://127.0.0.1:5000/scan", {
    // Send request to the Python backend
    method: "POST", // Use POST to send data
    headers: {
      "Content-Type": "application/json", // Set content type to JSON
    },
    body: JSON.stringify({ url: websiteURL }), // Convert URL into JSON
  })
    .then((response) => response.json()) // Parse JSON response from server
    .then((data) => {
      console.log(data); // Handle the data returned by the Python server
      alert("Scan complete: " + JSON.stringify(data));
    })
    .catch((error) => console.error("Error:", error));
}

function scanningMal() {
  const websiteURL = document.getElementById("websiteURL").value; // Get the URL from input
  fetch("http://127.0.0.1:5000/mals", {
    // Send request to the Python backend
    method: "POST", // Use POST to send data
    headers: {
      "Content-Type": "application/json", // Set content type to JSON
    },
    body: JSON.stringify({ url: websiteURL }), // Convert URL into JSON
  })
    .then((response) => response.json()) // Parse JSON response from server
    .then((data) => {
      console.log(data); // Handle the data returned by the Python server
      alert("Scan complete: " + JSON.stringify(data));
    })
    .catch((error) => console.error("Error:", error));
}

function ssl() {
  const websiteURL = document.getElementById("websiteURL").value; // Get the URL from input
  fetch("http://127.0.0.1:5000/ssl", {
    // Send request to the Python backend
    method: "POST", // Use POST to send data
    headers: {
      "Content-Type": "application/json", // Set content type to JSON
    },
    body: JSON.stringify({ url: websiteURL }), // Convert URL into JSON
  })
    .then((response) => response.json()) // Parse JSON response from server
    .then((data) => {
      console.log(data); // Handle the data returned by the Python server
      alert("Scan complete: " + JSON.stringify(data));
    })
    .catch((error) => console.error("Error:", error));
}

function peechekilinks() {
  const websiteURL = document.getElementById("websiteURL").value; // Get the URL from input
  fetch("http://127.0.0.1:5000/backlinks", {
    // Send request to the Python backend
    method: "POST", // Use POST to send data
    headers: {
      "Content-Type": "application/json", // Set content type to JSON
    },
    body: JSON.stringify({ url: websiteURL }), // Convert URL into JSON
  })
    .then((response) => response.json()) // Parse JSON response from server
    .then((data) => {
      console.log(data); // Handle the data returned by the Python server
      alert("Scan complete: " + JSON.stringify(data));
    })
    .catch((error) => console.error("Error:", error));
}
function domain() {
  const websiteURL = document.getElementById("websiteURL").value; // Get the URL from input
  fetch("http://127.0.0.1:5000/whois", {
    // Send request to the Python backend
    method: "POST", // Use POST to send data
    headers: {
      "Content-Type": "application/json", // Set content type to JSON
    },
    body: JSON.stringify({ url: websiteURL }), // Convert URL into JSON
  })
    .then((response) => response.json()) // Parse JSON response from server
    .then((data) => {
      console.log(data); // Handle the data returned by the Python server
      alert("Scan complete: " + JSON.stringify(data));
    })
    .catch((error) => console.error("Error:", error));
}

function TrustScore() {
  const websiteURL = document.getElementById("websiteURL").value; // Get the URL from input
  fetch("http://127.0.0.1:5000/Tscore", {
    // Send request to the Python backend
    method: "POST", // Use POST to send data
    headers: {
      "Content-Type": "application/json", // Set content type to JSON
    },
    body: JSON.stringify({ url: websiteURL }), // Convert URL into JSON
  })
    .then((response) => response.json()) // Parse JSON response from server
    .then((data) => {
      console.log(data); // Handle the data returned by the Python server
      alert("Scan complete: " + JSON.stringify(data));
    })
    .catch((error) => console.error("Error:", error));
}

function all_scans() {
  const websiteURL = document.getElementById("websiteURL").value; // Get the URL from input
  localStorage.setItem("scannedURL", websiteURL);
  // Disable the input field during the scan to avoid multiple submissions
  document.getElementById("websiteURL").disabled = true;

  // Set a timeout for the scan to avoid it running indefinitely
  const controller = new AbortController();
  const signal = controller.signal;
  const timeout = setTimeout(() => {
    controller.abort(); // Abort the fetch request if it takes too long
    alert("Scan timed out. Please try again later.");
    // Re-enable the input after timeout
    document.getElementById("websiteURL").disabled = false;
  }, 10000000); // 80 seconds timeout (you can adjust this as necessary)

  fetch("http://127.0.0.1:5000/runAllScans", {
    // Send request to the Python backend
    method: "POST", // Use POST to send data
    headers: {
      "Content-Type": "application/json", // Set content type to JSON
    },
    body: JSON.stringify({ url: websiteURL }), // Convert URL into JSON
    signal: signal, // Attach the timeout controller
  })
    .then((response) => response.json()) // Parse JSON response from server
    .then((data) => {
      // Handle the data returned by the Python server
      console.log("Scan completed:", data);

      // Check and update the HTML with the fetched data if elements exist
      if (document.getElementById("urlDetails")) {
        document.getElementById("urlDetails").innerHTML = websiteURL;
      }
      if (document.getElementById("domainName")) {
        document.getElementById("domainName").innerHTML =
          data["DomainInformation"]["Domain Name"];
      }
      if (document.getElementById("registrar")) {
        document.getElementById("registrar").innerHTML =
          data["DomainInformation"]["Registrar"];
      }
      if (document.getElementById("creationDate")) {
        document.getElementById("creationDate").innerHTML =
          data["DomainInformation"]["Creation Date"];
      }
      if (document.getElementById("expirationDate")) {
        document.getElementById("expirationDate").innerHTML =
          data["DomainInformation"]["Expiration Date"];
      }
      if (document.getElementById("domainAge")) {
        document.getElementById("domainAge").innerHTML =
          data["DomainInformation"]["Domain_Age"];
      }
      if (document.getElementById("nameServers")) {
        document.getElementById("nameServers").innerHTML =
          data["DomainInformation"]["Name Servers"];
      }
      
    
      if (data["SSLinfo"]) {
        const sslInfo = data["SSLinfo"];
        if (document.getElementById("IPAddress")) {
          document.getElementById("IPAddress").innerHTML = sslInfo["ip"];
        }
        if (document.getElementById("Valid")) {
          document.getElementById("Valid").innerHTML = sslInfo["IsExpired"] === 0 ? "Not Valid" : "Valid";
      }
      
        if (document.getElementById("Hosting")) {
          document.getElementById("Hosting").innerHTML = sslInfo["Hosting Location"];
        }
        if (document.getElementById("connectionType")) {
          document.getElementById("connectionType").innerHTML =sslInfo["connection Type"];
        }
        if (document.getElementById("issueDate")) {
          document.getElementById("issueDate").innerHTML = sslInfo["IssueDate"];
        }
        if (document.getElementById("expiryDate")) {
          document.getElementById("expiryDate").innerHTML =
            sslInfo["expiryDate"];
        }
        if (document.getElementById("issuer")) {
          document.getElementById("issuer").innerHTML = sslInfo["Issuer"];
        }
        if (document.getElementById("domain")) {
          document.getElementById("domain").innerHTML = sslInfo["domain"] ? "Domain Matches SSL Certificate" : "Domain Does Not Match SSL Certificate";
        }
      
        if (document.getElementById("revocation")) {
          document.getElementById("revocation").innerHTML = sslInfo["Revoked"] ? "Revoked" : "Not Revoked";
        }
      
      } else {
        console.error("SSLinfo is missing or null");
      }

      if (document.getElementById("vulnerabilityCount")) {
        document.getElementById("vulnerabilityCount").innerHTML =
          data["vulner"]["Total_Vuls"];
      }
      if (document.getElementById("highCount")) {
        document.getElementById("highCount").innerHTML =
          data["vulner"]["RiskLevels"][0];
      }
      if (document.getElementById("mediumCount")) {
        document.getElementById("mediumCount").innerHTML =
          data["vulner"]["RiskLevels"][1];
      }
      if (document.getElementById("lowCount")) {
        document.getElementById("lowCount").innerHTML =
          data["vulner"]["RiskLevels"][2];
      }
      if (document.getElementById("informationalCount")) {
        document.getElementById("informationalCount").innerHTML =
          data["vulner"]["RiskLevels"][0];
      }
      if (document.getElementById("Description")) {
        document.getElementById("Description").innerHTML =
          data["vulner"]["list_of_vuls"];
      }
      if (document.getElementById("VulScore")) {
        document.getElementById("VulScore").innerHTML =
          data["vulner"]["vulScore"];
      }
      if (document.getElementById("Score")) {
        document.getElementById("Score").innerHTML =
          data["Trust"]["Trust Score"];
      }
      // Re-enable the input field after the scan is completed
      document.getElementById("websiteURL").disabled = false;
      alert("Scan completed successfully!");
      localStorage.setItem("scanResult", JSON.stringify(data));
      window.location.href = "scan_result.html";
    })
      fetch("http://127.0.0.1:5000/backlinks", {
      // Send request to the Python backend
      method: "POST", // Use POST to send data
      headers: {
        "Content-Type": "application/json", // Set content type to JSON
      },
      body: JSON.stringify({ url: websiteURL }), // Convert URL into JSON
    })
      .then((response) => response.json()) // Parse JSON response from server
      .then((data) => {
         // Handle the data returned by the Python server
        
      })
      .catch((error) => console.error("Error:", error));
      
      if (document.getElementById("Backlinks")) {
        document.getElementById("Backlinks").innerHTML = data["backlinks"]["Total Backlinks"];
      }
      if (document.getElementById("Follow_Links")) {
        document.getElementById("Follow_Links").innerHTML = data["backlinks"]["Follow Links"];
      }
      if (document.getElementById("NoFollow_Links")) {
        document.getElementById("NoFollow_Links").innerHTML = data["backlinks"]["No-Follow Links"];
      }
      if (document.getElementById("Secure_Links")) {
        document.getElementById("Secure_Links").innerHTML = data["backlinks"]["Secure Links"];
      }
      if (document.getElementById("NotSecure_Links")) {
        document.getElementById("NotSecure_Links").innerHTML = data["backlinks"]["Not Secure Links"];
      }
      
  


}

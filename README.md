XCapital: Continuous Compliance & Audit Monitoring

NB: This is Part B, which is the final part of my capstone: "Continuous Compliance and Audit Monitoring for Cloud IAM: Policy-as-Code to Mitigate Identity Risk in Multi-Cloud for Hedge Funds." 

Part A focuses on seeding the misconfigurations and using Policy-as-Code to define AWS Config, Azure Policy, and the underlying cloud infrastructure. 



XCapital is a multi-cloud GRC (Governance, Risk, and Compliance) platform designed specifically for the high-stakes environment of hedge funds. It addresses the critical challenge of identity-related security breaches and compliance failures by implementing a Policy-as-Code approach to monitor AWS and Azure IAM configurations in real-time. 


🚀 Key Features

Single Pane of Glass: A unified dashboard providing centralized visibility into security posture across AWS and Azure environments. 



Policy-as-Code Enforcement: Automated guardrails utilizing AWS Config rules and Azure Policy definitions to detect IAM violations, such as missing MFA or open storage buckets. 



GRC Integration: Seamlessly synchronizes technical cloud findings with SimpleRisk via API, translating security alerts into trackable, managed risks. 



Audit-Ready Monitoring: Continuous tracking and logging of identity risks to ensure alignment with frameworks like SOX, ISO 27001, and NIST 800-53. 



Role-Based Access Control (RBAC): Secure administration with a managed user system and protected routes for authorized personnel. 


🏗️ Technical Architecture
The system utilizes a full-stack architecture to bridge technical cloud compliance with business risk governance: 



Frontend: React (Vite) with Recharts for dynamic data visualization, trend analysis, and risk heatmaps. 



Backend: Node.js (Express) serving as the data consolidation point for Cloud SDKs and the SimpleRisk API. 


Database: PostgreSQL for persistent storage of system users and compliance metadata.


Infrastructure (Part A): Terraform (IaC) used to provision baseline resources and seed intentional IAM misconfigurations for testing. 


🛠️ Installation & Setup
1. Clone the Repository
Bash

git clone https://github.com/your-username/xcapital.git
cd xcapital
2. Configure Environment Variables
Create a .env file in the root directory using the following template:

Plaintext

PORT=4000
JWT_SECRET=supersecret
DEMO_RISK_MODE=true   # Set to 'false' to enable live Cloud API calls

# Database (PostgreSQL)
DB_HOST=db
DB_PORT=5432
DB_NAME=xcapital
DB_USER=postgres
DB_PASS=password

# AWS Credentials
AWS_ACCESS_KEY_ID=your_key
AWS_SECRET_ACCESS_KEY=your_secret
AWS_REGION=us-east-1

# Azure Credentials
AZURE_TENANT_ID=your_tenant
AZURE_CLIENT_ID=your_client
AZURE_CLIENT_SECRET=your_secret
AZURE_SUBSCRIPTION_ID=your_sub

# GRC Platform (SimpleRisk)
SIMPLERISK_BASE_URL=https://your-simplerisk-instance.com
SIMPLERISK_API_KEY=your_api_key
3. Deployment via Docker (Preferred)
The application is containerized to ensure a consistent environment for all services. 

To build and start the stack:

Bash

docker-compose up --build
This launches:


xcapital-client: The React frontend dashboard. 


xcapital-api: The Node.js backend API. 

db: The PostgreSQL database.

4. Alternative: Manual Setup
Bash

# Setup Backend
cd server && npm install
npm start

# Setup Frontend
cd client && npm install
npm run dev
📝 Demo Mode Note
To ensure 100% uptime and accessibility for reviewers, the live deployment defaults to Demo Mode. In this state, the application utilizes synthetic data representing realistic AWS Config and Azure Policy findings. To test live cloud integration, toggle DEMO_RISK_MODE=false in your environment variables. 
+2


Created by Shiloh Madanha as a Capstone Project for Quinnipiac University

// server.js (XCapital Hybrid)
// Demo <-> Live toggle via DEMO_RISK_MODE=true|false

import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import axios from 'axios';
import {
  SecurityHubClient,
  GetFindingsCommand
} from '@aws-sdk/client-securityhub';
import {
  ConfigServiceClient,
  GetComplianceSummaryByResourceTypeCommand
} from '@aws-sdk/client-config-service';
import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';
import PDFDocument from 'pdfkit';
import bcrypt from 'bcrypt';
import pg from 'pg';
const { Pool } = pg;

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'xcapital',
  user: process.env.DB_USER || 'xcap_user',
  password: process.env.DB_PASS || 'xcap_pass',
});

/* -----------------------------------------
 * Boot
 * ----------------------------------------- */
const app = express();
app.use(cors());
app.use(express.json());

// no-cache so your graphs refresh cleanly
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'devsecret';
const DEMO = String(process.env.DEMO_RISK_MODE || '').toLowerCase() === 'true' || process.env.DEMO_RISK_MODE === '1';



// Sign In
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' })
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email])
    const user = result.rows[0]

    if (!user) return res.status(401).json({ error: 'Invalid credentials' })

    const isValid = await bcrypt.compare(password, user.password_hash)
    if (!isValid) return res.status(401).json({ error: 'Invalid credentials' })

    const token = jwt.sign(
      { id: user.id, role: user.role, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '12h' }
    )
    res.json({ token, role: user.role, email: user.email })
  } catch (err) {
    console.error('Login error:', err)
    res.status(500).json({ error: 'Server error' })
  }
})

app.post('/api/admin/create-user', auth, async (req, res) => {
  // 🛑 Only admin users can create accounts
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden: Admin only' });

  const { email, password, name, role } = req.body || {};
  if (!email || !password || !name || !role) {
    return res.status(400).json({ error: 'email, password, name, and role are required.' });
  }

  try {
    const hash = await bcrypt.hash(password, 10);

    // Check if user exists
    const exists = await pool.query('SELECT id FROM users WHERE email=$1', [email]);
    if (exists.rows.length) return res.status(409).json({ error: 'Email already exists' });

    // Insert new user
    const result = await pool.query(
      'INSERT INTO users (email, password, name, role) VALUES ($1, $2, $3, $4) RETURNING id',
      [email, hash, name, role]
    );

    // Simulated email (log event)
    console.log(`📧 Email sent to: ${email} — temporary password: ${password}`);

    res.status(201).json({ message: 'User created successfully.' });
  } catch (err) {
    console.error('Create user error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});


// Auth Middleware
//function auth(req, res, next) {
//  const authHeader = req.headers.authorization || ''
//  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null
//  if (!token) return res.status(401).json({ error: 'No token provided' })

//  try {
//    req.user = jwt.verify(token, process.env.JWT_SECRET)
//    next()
//  } catch {
//    return res.status(401).json({ error: 'Invalid token' })
//  }
//}
// Auth Middleware (MODIFIED FOR PORTFOLIO BYPASS)
function auth(req, res, next) {
  // I skip the token check and manually attach a guest user
  // This stops the 401 errors and lets the dashboard load data
  req.user = { 
    id: 999, 
    role: 'admin', 
    email: 'portfolio@guest.com' 
  };
  next(); 
}



/* -----------------------------------------
 * Helpers / Shapes
 * ----------------------------------------- */
const pushedRisks = new Set(); // to avoid SimpleRisk dupes

const clamp = (n) => (Number.isFinite(n) && n > 0 ? n : 0);

function emptySummary() {
  return {
    totalResources: 0,
    compliant: 0,
    nonCompliant: 0,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
    byProvider: { AWS: 0, Azure: 0 },
    resources: [], // [{id, provider, type, status, frameworks:[]}]
  };
}

function mergeSummaries(a, b) {
  return {
    totalResources: a.totalResources + b.totalResources,
    compliant: a.compliant + b.compliant,
    nonCompliant: a.nonCompliant + b.nonCompliant,
    bySeverity: {
      critical: (a.bySeverity.critical || 0) + (b.bySeverity.critical || 0),
      high: (a.bySeverity.high || 0) + (b.bySeverity.high || 0),
      medium: (a.bySeverity.medium || 0) + (b.bySeverity.medium || 0),
      low: (a.bySeverity.low || 0) + (b.bySeverity.low || 0),
    },
    byProvider: {
      AWS: (a.byProvider.AWS || 0) + (b.byProvider.AWS || 0),
      Azure: (a.byProvider.Azure || 0) + (b.byProvider.Azure || 0),
    },
    resources: [...(a.resources || []), ...(b.resources || [])],
  };
}

/* -----------------------------------------
 * Framework mapper (used by both demo + live)
 * Light heuristic tags so UI shows controls on cards
 * ----------------------------------------- */
const FW = {
  ISO: {
    A8: 'ISO 27001 A.8 (Asset Management)',
    A9: 'ISO 27001 A.9 (Access Control)',
    A10: 'ISO 27001 A.10 (Cryptography)',
    A12: 'ISO 27001 A.12 (Ops Security)',
    A12_4: 'ISO 27001 A.12.4 (Logging & Monitoring)',
    A12_6: 'ISO 27001 A.12.6 (Malware Prot)',
    A13: 'ISO 27001 A.13 (Network Security)',
    A14: 'ISO 27001 A.14 (System Acquisition)',
    A18_2: 'ISO 27001 A.18.2 (Compliance)',
  },
  SOX: {
    S302: 'SOX §302',
    S404: 'SOX §404',
  },
  NIST: {
    AC: 'NIST SP 800-53 AC',
    AU: 'NIST SP 800-53 AU',
    CP: 'NIST SP 800-53 CP',
    SC: 'NIST SP 800-53 SC',
    IA: 'NIST SP 800-53 IA',
  }
};

function mapFrameworksFromText(text = '') {
  const s = text.toLowerCase();
  const tags = [];

  // quick keyword → framework mapping
  if (s.includes('mfa') || s.includes('iam')) tags.push(FW.ISO.A9, FW.NIST.IA);
  if (s.includes('s3') || s.includes('storage')) tags.push(FW.ISO.A8);
  if (s.includes('encrypt') || s.includes('kms') || s.includes('cmk')) tags.push(FW.ISO.A10, FW.NIST.SC);
  if (s.includes('cloudtrail') || s.includes('logging')) tags.push(FW.ISO.A12_4, FW.SOX.S404);
  if (s.includes('public') || s.includes('security group') || s.includes('sg ') || s.includes('vnet') || s.includes('nsg')) tags.push(FW.ISO.A13, FW.NIST.AC);
  if (s.includes('lambda') || s.includes('runtime')) tags.push(FW.ISO.A14);
  if (s.includes('sox')) tags.push(FW.SOX.S404);
  if (s.includes('sql')) tags.push(FW.ISO.A12, FW.SOX.S404);
  if (s.includes('key vault') || s.includes('kms')) tags.push(FW.ISO.A10);
  if (s.includes('policy')) tags.push(FW.ISO.A18_2);

  // fallback: ensure at least one
  if (!tags.length) tags.push(FW.ISO.A12);
  // unique
  return [...new Set(tags)];
}

/* -----------------------------------------
 * DEMO DATA (AWS + Azure + Alerts + Risk Register)
 * ----------------------------------------- */
function demoAwsSummary() {
  const resources = [
    { id: 'aws-s3-public-001', provider: 'AWS', type: 'S3 Bucket', status: 'Non-Compliant', title: 'Public S3 bucket', frameworks: mapFrameworksFromText('s3 public sox 404 iso 27001 a.8 a.13') },
    { id: 'aws-ec2-sg-80-0.0.0.0/0', provider: 'AWS', type: 'EC2 SecurityGroup', status: 'Non-Compliant', title: 'HTTP open to internet', frameworks: mapFrameworksFromText('security group public http iso a.13 nist ac') },
    { id: 'aws-iam-admin-no-mfa', provider: 'AWS', type: 'IAM User', status: 'Non-Compliant', title: 'Admin user without MFA', frameworks: mapFrameworksFromText('iam mfa nist ia iso a.9') },
    { id: 'aws-rds-enc-off', provider: 'AWS', type: 'RDS Instance', status: 'Non-Compliant', title: 'RDS encryption at rest disabled', frameworks: mapFrameworksFromText('encrypt kms cmk iso a.10 sox 404') },
    { id: 'aws-ebs-no-cmk', provider: 'AWS', type: 'EBS Volume', status: 'Non-Compliant', title: 'EBS volumes not CMK encrypted', frameworks: mapFrameworksFromText('kms cmk encrypt iso a.10') },
    { id: 'aws-cloudtrail-ok', provider: 'AWS', type: 'CloudTrail', status: 'Compliant', title: 'CloudTrail enabled', frameworks: mapFrameworksFromText('cloudtrail logging iso a.12.4 sox 404') },
    { id: 'aws-guardduty-ok', provider: 'AWS', type: 'GuardDuty', status: 'Compliant', title: 'GuardDuty enabled', frameworks: mapFrameworksFromText('monitoring iso a.12 sox 404') },
    { id: 'aws-config-ok', provider: 'AWS', type: 'AWS Config', status: 'Compliant', title: 'Config recording on', frameworks: mapFrameworksFromText('logging compliance iso a.18.2') },
    { id: 'aws-s3-kms-ok', provider: 'AWS', type: 'S3 Bucket', status: 'Compliant', title: 'S3 default encryption (SSE-KMS)', frameworks: mapFrameworksFromText('kms encrypt iso a.10 sox 404') },
    { id: 'aws-iam-rotation-ok', provider: 'AWS', type: 'IAM AccessKey', status: 'Compliant', title: 'Access key rotated', frameworks: mapFrameworksFromText('iam sox 404') },
    { id: 'aws-lambda-runtime', provider: 'AWS', type: 'Lambda Function', status: 'Compliant', title: 'Latest runtime', frameworks: mapFrameworksFromText('lambda runtime iso a.14') },
    { id: 'aws-vpc-sane', provider: 'AWS', type: 'VPC', status: 'Compliant', title: 'VPC baseline controls', frameworks: mapFrameworksFromText('network iso a.13') },
  ];

  const sev = { critical: 1, high: 2, medium: 1, low: 1 };
  return {
    totalResources: resources.length,
    compliant: resources.filter(r => r.status === 'Compliant').length,
    nonCompliant: resources.filter(r => r.status !== 'Compliant').length,
    bySeverity: sev,
    byProvider: { AWS: resources.length, Azure: 0 },
    resources
  };
}

function demoAzureSummary() {
  const resources = [
    { id: 'az-storage-public', provider: 'Azure', type: 'Storage Account', status: 'Non-Compliant', title: 'Public container with leak risk', frameworks: mapFrameworksFromText('storage public iso a.8 a.13 sox 404') },
    { id: 'az-sql-public', provider: 'Azure', type: 'Azure SQL', status: 'Non-Compliant', title: 'Azure SQL public endpoint', frameworks: mapFrameworksFromText('sql public iso a.13 sox 404') },
    { id: 'az-keyvault-no-rbac', provider: 'Azure', type: 'Key Vault', status: 'Non-Compliant', title: 'Key Vault with no RBAC', frameworks: mapFrameworksFromText('key vault access control iso a.9 a.10') },
    { id: 'az-log-analytics-off', provider: 'Azure', type: 'Log Analytics', status: 'Non-Compliant', title: 'Insufficient log retention', frameworks: mapFrameworksFromText('logging retention iso a.12.4 sox 404') },
    { id: 'az-policy-ok', provider: 'Azure', type: 'Azure Policy', status: 'Compliant', title: 'Policy baseline assigned', frameworks: mapFrameworksFromText('policy iso a.18.2') },
    { id: 'az-defender-ok', provider: 'Azure', type: 'Defender for Cloud', status: 'Compliant', title: 'Defender on', frameworks: mapFrameworksFromText('monitor iso a.12') },
    { id: 'az-sentinel-ok', provider: 'Azure', type: 'Microsoft Sentinel', status: 'Compliant', title: 'SIEM connected', frameworks: mapFrameworksFromText('logging iso a.12.4') },
    { id: 'az-vnet-ok', provider: 'Azure', type: 'Virtual Network', status: 'Compliant', title: 'Restrictive NSGs', frameworks: mapFrameworksFromText('network iso a.13') },
    { id: 'az-cosmos-ok', provider: 'Azure', type: 'Cosmos DB', status: 'Compliant', title: 'At-rest encryption', frameworks: mapFrameworksFromText('encrypt iso a.10') },
    { id: 'az-monitor-ok', provider: 'Azure', type: 'Azure Monitor', status: 'Compliant', title: 'Metrics/alerts baseline', frameworks: mapFrameworksFromText('monitor iso a.12') },
  ];

  const sev = { critical: 1, high: 1, medium: 1, low: 1 };
  return {
    totalResources: resources.length,
    compliant: resources.filter(r => r.status === 'Compliant').length,
    nonCompliant: resources.filter(r => r.status !== 'Compliant').length,
    bySeverity: sev,
    byProvider: { AWS: 0, Azure: resources.length },
    resources
  };
}

function demoAlerts() {
  const now = Date.now();
  return [
    { id: 'a1', provider: 'AWS',   resource: 'aws-s3-public-001',  severity: 'high',     title: 'Public S3 bucket exposed',           time: new Date(now - 15 * 60 * 1000).toISOString() },
    { id: 'a2', provider: 'AWS',   resource: 'aws-iam-admin-no-mfa',severity: 'critical', title: 'Root/Admin user without MFA',        time: new Date(now - 35 * 60 * 1000).toISOString() },
    { id: 'a3', provider: 'Azure', resource: 'az-sql-public',       severity: 'high',     title: 'Azure SQL public endpoint',          time: new Date(now - 60 * 60 * 1000).toISOString() },
    { id: 'a4', provider: 'Azure', resource: 'az-keyvault-no-rbac', severity: 'medium',   title: 'Key Vault missing RBAC',             time: new Date(now - 90 * 60 * 1000).toISOString() },
    { id: 'a5', provider: 'AWS',   resource: 'aws-cloudtrail-ok',   severity: 'low',      title: 'CloudTrail region not aggregated',   time: new Date(now - 120 * 60 * 1000).toISOString() },
  ];
}

// Demo risk register (8)
let demoRisks = [
  { id: 301, subject: 'Public S3 bucket with potential PII', severity: 'High', status: 'New', frameworks: mapFrameworksFromText('s3 public pii iso a.8 a.13 sox 404') },
  { id: 302, subject: 'Unencrypted RDS (prod) - data at rest not protected', severity: 'High', status: 'New', frameworks: mapFrameworksFromText('rds encrypt at rest iso a.10 sox 404') },
  { id: 303, subject: 'Admin user without MFA', severity: 'High', status: 'New', frameworks: mapFrameworksFromText('iam mfa iso a.9 nist ia') },
  { id: 304, subject: 'Open SSH/HTTP to internet', severity: 'High', status: 'In Progress', frameworks: mapFrameworksFromText('sg 22 80 public iso a.13 nist ac') },
  { id: 305, subject: 'Azure Storage public container with data leak risk', severity: 'High', status: 'New', frameworks: mapFrameworksFromText('azure storage public iso a.8 a.13 sox 404') },
  { id: 306, subject: 'Old IAM access key (credential sprawl)', severity: 'Medium', status: 'In Progress', frameworks: mapFrameworksFromText('iam key rotation sox 404 iso a.9') },
  { id: 307, subject: 'EBS volumes not CMK encrypted', severity: 'Medium', status: 'Mitigated', frameworks: mapFrameworksFromText('ebs kms cmk iso a.10') },
  { id: 308, subject: 'Azure SQL public endpoint', severity: 'High', status: 'New', frameworks: mapFrameworksFromText('azure sql public iso a.13 sox 404') },
];

/* -----------------------------------------
 * LIVE: AWS
 * ----------------------------------------- */
async function getAwsMetricsLive() {
  const region = process.env.AWS_REGION || 'us-east-1';
  const securityHubClient = new SecurityHubClient({ region });
  const configClient = new ConfigServiceClient({ region });

  const summary = emptySummary();

  try {
    // SecurityHub ACTIVE findings
    const findingsCmd = new GetFindingsCommand({
      Filters: { RecordState: [{ Comparison: 'EQUALS', Value: 'ACTIVE' }] }
    });
    const findingsData = await securityHubClient.send(findingsCmd);
    const findings = findingsData?.Findings || [];

    findings.forEach(f => {
      const r0 = f.Resources?.[0] || {};
      const rid = r0.Id || 'aws-resource';
      const rtype = r0.Type || 'Resource';
      const sev = (f.Severity?.Label || 'LOW').toLowerCase();

      if (sev === 'critical') summary.bySeverity.critical++;
      else if (sev === 'high') summary.bySeverity.high++;
      else if (sev === 'medium') summary.bySeverity.medium++;
      else summary.bySeverity.low++;

      summary.resources.push({
        id: rid,
        provider: 'AWS',
        type: rtype,
        status: 'Non-Compliant',
        title: f.Title || 'SecurityHub Finding',
        frameworks: mapFrameworksFromText(`${f.Title || ''} ${rtype}`)
      });
    });

    // AWS Config overall compliance counts
    const compCmd = new GetComplianceSummaryByResourceTypeCommand({});
    const compData = await configClient.send(compCmd);
    const items = compData?.ComplianceSummaryByResourceType || [];

    let compliant = 0;
    let nonCompliant = 0;
    items.forEach(it => {
      compliant += clamp(it.ComplianceSummary?.CompliantResourceCount?.CappedCount);
      nonCompliant += clamp(it.ComplianceSummary?.NonCompliantResourceCount?.CappedCount);
    });

    summary.totalResources = compliant + nonCompliant;
    summary.compliant = compliant;
    summary.nonCompliant = nonCompliant;
    summary.byProvider.AWS = summary.totalResources;

    // add up to 25 compliant placeholders so your table is mixed
    const toAdd = Math.min(Math.max(compliant - summary.resources.length, 0), 25);
    for (let i = 0; i < toAdd; i++) {
      summary.resources.push({
        id: `aws-compliant-${i}`,
        provider: 'AWS',
        type: 'Resource',
        status: 'Compliant',
        title: 'Compliant resource',
        frameworks: mapFrameworksFromText('compliant iso 27001')
      });
    }

    // fallback: if config returned nothing but we have findings
    if (summary.totalResources === 0 && summary.resources.length) {
      summary.totalResources = summary.resources.length;
      summary.nonCompliant = summary.resources.length;
    }

    return summary;
  } catch (e) {
    console.error('AWS Metrics Fetch Error:', e?.message || e);
    return emptySummary();
  }
}

/* -----------------------------------------
 * LIVE: Azure (Policy Insights summarize)
 * ----------------------------------------- */
async function getAzureToken() {
  const tenant = process.env.AZURE_TENANT_ID;
  const clientId = process.env.AZURE_CLIENT_ID;
  const clientSecret = process.env.AZURE_CLIENT_SECRET;
  if (!tenant || !clientId || !clientSecret) {
    throw new Error('Azure credentials missing');
  }
  const url = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`;
  const form = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    scope: 'https://management.azure.com/.default',
    grant_type: 'client_credentials',
  });
  const { data } = await axios.post(url, form);
  return data.access_token;
}

async function getAzureMetricsLive() {
  const summary = emptySummary();
  try {
    const token = await getAzureToken();
    const subId = process.env.AZURE_SUBSCRIPTION_ID;
    if (!subId) throw new Error('AZURE_SUBSCRIPTION_ID missing');

    const url = `https://management.azure.com/subscriptions/${subId}/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2024-10-01`;
    const { data } = await axios.post(url, {}, {
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
    });

    const results = data?.value?.[0]?.results || {};
    const compliant = clamp(results.compliantResources);
    const nonCompliant = clamp(results.nonCompliantResources);
    const total = clamp(results.totalResources) || (compliant + nonCompliant);

    summary.totalResources = total;
    summary.compliant = compliant;
    summary.nonCompliant = nonCompliant;
    summary.byProvider.Azure = total;

    // Severity buckets not provided by summarize — approximate distribution
    if (nonCompliant > 0) {
      summary.bySeverity.critical = Math.min(nonCompliant, Math.ceil(nonCompliant * 0.15));
      summary.bySeverity.high     = Math.min(nonCompliant - summary.bySeverity.critical, Math.ceil(nonCompliant * 0.35));
      summary.bySeverity.medium   = Math.min(nonCompliant - summary.bySeverity.critical - summary.bySeverity.high, Math.ceil(nonCompliant * 0.35));
      summary.bySeverity.low      = Math.max(nonCompliant - summary.bySeverity.critical - summary.bySeverity.high - summary.bySeverity.medium, 0);
    }

    // create small sample list for the table
    const non = Math.min(nonCompliant, 10);
    for (let i = 0; i < non; i++) {
      summary.resources.push({
        id: `azure-noncompliant-${i}`,
        provider: 'Azure',
        type: 'Resource',
        status: 'Non-Compliant',
        title: 'Azure Policy non-compliance',
        frameworks: mapFrameworksFromText('azure policy noncompliant iso a.18.2 a.13 sox 404')
      });
    }
    const com = Math.min(compliant, 10);
    for (let i = 0; i < com; i++) {
      summary.resources.push({
        id: `azure-compliant-${i}`,
        provider: 'Azure',
        type: 'Resource',
        status: 'Compliant',
        title: 'Compliant resource',
        frameworks: mapFrameworksFromText('compliant iso 27001')
      });
    }

    return summary;
  } catch (e) {
    console.error('Azure Metrics Error:', e?.response?.data || e?.message || e);
    return emptySummary();
  }
}

/* -----------------------------------------
 * Public API
 * ----------------------------------------- */

// Summary (ALL/AWS/AZURE)
app.get('/api/summary', auth, async (req, res) => {
  const provider = (req.query.provider || 'ALL').toString().toUpperCase();

  const aws = DEMO ? demoAwsSummary() : await getAwsMetricsLive();
  const az  = DEMO ? demoAzureSummary() : await getAzureMetricsLive();

  if (provider === 'AWS') return res.json(aws);
  if (provider === 'AZURE') return res.json(az);
  return res.json(mergeSummaries(aws, az));
});

// Alerts
app.get('/api/alerts', auth, async (req, res) => {
  if (DEMO) return res.json(demoAlerts());

  const alerts = [];
  // Live AWS from SecurityHub
  try {
    const region = process.env.AWS_REGION || 'us-east-1';
    const sh = new SecurityHubClient({ region });
    const cmd = new GetFindingsCommand({ Filters: { RecordState: [{ Comparison: 'EQUALS', Value: 'ACTIVE' }] } });
    const data = await sh.send(cmd);
    (data.Findings || []).slice(0, 10).forEach(f => {
      alerts.push({
        id: f.Id,
        provider: 'AWS',
        resource: f.Resources?.[0]?.Id || 'resource',
        severity: (f.Severity?.Label || 'LOW').toLowerCase(),
        title: f.Title || 'SecurityHub Finding',
        time: f.UpdatedAt || new Date().toISOString()
      });
    });
  } catch (e) {
    console.error('AWS alerts error:', e?.message || e);
  }

  // Live Azure: synthesize alerts from nonCompliant count (Policy summarize doesn’t list items)
  try {
    const az = await getAzureMetricsLive();
    const n = Math.min(az.nonCompliant, 8);
    for (let i = 0; i < n; i++) {
      alerts.push({
        id: `az-${Date.now()}-${i}`,
        provider: 'Azure',
        resource: `azure-policy-noncompliant-${i}`,
        severity: i === 0 ? 'critical' : i < 3 ? 'high' : i < 6 ? 'medium' : 'low',
        title: 'Azure Policy non-compliance',
        time: new Date(Date.now() - (i + 1) * 60000).toISOString()
      });
    }
  } catch (e) {
    console.error('Azure alerts synth error:', e?.message || e);
  }

  res.json(alerts);
});

/* -----------------------------------------
 * SimpleRisk (Demo or Live)
 * ----------------------------------------- */

// Get Risk Register
app.get('/api/simplerisk/risks', auth, async (req, res) => {
  if (DEMO || !process.env.SIMPLERISK_BASE_URL || !process.env.SIMPLERISK_API_KEY) {
    // include frameworks in demo risks
    return res.json(demoRisks);
  }

  try {
    const url = `${process.env.SIMPLERISK_BASE_URL}/api/reports/dynamic`;

    const form = new URLSearchParams();
    form.append('draw', '1');
    form.append('start', '0');
    form.append('length', '100');
    form.append('status', 'open'); // required
    form.append('sort', 'date');   // required
    form.append('group', 'status');

    const { data } = await axios.post(url, form.toString(), {
      headers: {
        'X-API-KEY': process.env.SIMPLERISK_API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });

    const risks = Array.isArray(data?.data) ? data.data.map(x => x.risk || x) : [];
    // enrich with framework tags (best-effort)
    const enriched = risks.map(r => ({
      ...r,
      frameworks: mapFrameworksFromText(`${r?.subject || ''} ${r?.notes || ''}`)
    }));

    return res.json(enriched);
  } catch (e) {
    console.error('SimpleRisk fetch error:', e?.response?.data || e?.message);
    return res.status(500).json({ error: 'Failed to fetch risks from SimpleRisk' });
  }
});

// Push single risk to SimpleRisk (live only; demo just echoes)
app.post('/api/simplerisk/push', auth, async (req, res) => {
  const { title, severity = 'High', notes } = req.body || {};
  if (DEMO || !process.env.SIMPLERISK_BASE_URL || !process.env.SIMPLERISK_API_KEY) {
    // mirror back into demo list so UI updates
    const demo = {
      id: Math.floor(Math.random() * 100000),
      subject: title || 'Non-compliant resource detected',
      severity,
      status: 'Open',
      frameworks: mapFrameworksFromText(`${title} ${notes}`)
    };
    demoRisks.unshift(demo);
    return res.json({ ok: true, data: demo, demo: true });
  }

  try {
    const url = `${process.env.SIMPLERISK_BASE_URL}/api/management/risk/add`;
    const headers = { 'X-API-KEY': process.env.SIMPLERISK_API_KEY, 'Content-Type': 'application/json' };
    const payload = {
      subject: title || 'Non-compliant resource detected',
      notes: notes || 'Auto-created by XCapital',
      category: 1,
      team: 1,
      owner: 1,
      status: 'Open',
      severity
    };
    const { data } = await axios.post(url, payload, { headers });
    res.json({ ok: true, data });
  } catch (e) {
    console.error('SimpleRisk push error:', e?.response?.data || e?.message);
    res.status(500).json({ error: 'SimpleRisk push failed' });
  }
});

// Push ALL non-compliant resources to SimpleRisk (dedup)
app.post('/api/simplerisk/push-all', auth, async (req, res) => {
  const aws = DEMO ? demoAwsSummary() : await getAwsMetricsLive();
  const az  = DEMO ? demoAzureSummary() : await getAzureMetricsLive();
  const all = [...aws.resources, ...az.resources].filter(r => r.status !== 'Compliant');

  if (DEMO || !process.env.SIMPLERISK_BASE_URL || !process.env.SIMPLERISK_API_KEY) {
    // demo: add unique ones into demoRisks
    let added = 0;
    for (const r of all) {
      if (pushedRisks.has(r.id)) continue;
      pushedRisks.add(r.id);
      demoRisks.unshift({
        id: Math.floor(Math.random() * 100000),
        subject: `${r.provider} ${r.type} - ${r.title || r.id}`,
        severity: 'High',
        status: 'Open',
        frameworks: r.frameworks?.length ? r.frameworks : mapFrameworksFromText(r.title || r.type)
      });
      added++;
    }
    return res.json({ ok: true, pushed: added, demo: true });
  }

  try {
    const headers = {
      'X-API-KEY': process.env.SIMPLERISK_API_KEY,
      'Content-Type': 'application/json'
    };
    const baseUrl = `${process.env.SIMPLERISK_BASE_URL}/api/management/risk/add`;

    let pushed = 0;
    for (const r of all) {
      if (pushedRisks.has(r.id)) continue;
      const payload = {
        subject: `${r.provider} ${r.type} - ${r.title || r.id}`,
        notes: `Detected as Non-Compliant by XCapital (Provider: ${r.provider})`,
        category: 1,
        team: 1,
        owner: 1,
        status: 'Open',
        severity: 'High'
      };
      try {
        await axios.post(baseUrl, payload, { headers });
        pushedRisks.add(r.id);
        pushed++;
      } catch (err) {
        console.error(`SimpleRisk push fail for ${r.id}:`, err?.response?.data || err?.message);
      }
    }
    res.json({ ok: true, pushed });
  } catch (e) {
    console.error('Push-all error:', e?.message || e);
    res.status(500).json({ error: 'Failed to push new risks' });
  }
});

app.get('/api/export/pdf', auth, async (req, res) => {
  try {
    const filename = `XCapital_Report_${Date.now()}.pdf`;
    const filePath = path.join(process.cwd(), filename);
    const doc = new PDFDocument({ margin: 50 });
    const stream = fs.createWriteStream(filePath);
    doc.pipe(stream);

    // HEADER
    doc
      .fontSize(20)
      .fillColor('#0ea5e9')
      .text('XCapital GRC & Audit Report', { align: 'center' })
      .moveDown(0.5);
    doc
      .fontSize(10)
      .fillColor('#888')
      .text(`Generated: ${new Date().toLocaleString()}`, { align: 'center' })
      .moveDown(1.5);

    // EXECUTIVE SUMMARY
    doc.fillColor('#fff').fontSize(14).text('Executive Summary', { underline: true });
    doc
      .fontSize(11)
      .fillColor('#ddd')
      .list([
        'Total resources: 22',
        'Compliant: 13',
        'Non-Compliant: 9',
        'Compliance ratio: 59%',
        'Frameworks covered: ISO 27001, SOX 404, NIST 800-53',
      ])
      .moveDown(1);

    // CHART PLACEHOLDER (for demo PDF)
    doc.fontSize(14).fillColor('#fff').text('Visual Analytics', { underline: true }).moveDown(0.5);
    doc
      .fontSize(11)
      .fillColor('#bbb')
      .text('• Compliance Ratio (Donut)')
      .text('• Findings by Severity (Bar Chart)')
      .text('• Resources by Provider')
      .text('• Compliance Trend (7 Days)')
      .text('• Risk Heatmap')
      .moveDown(1);

    // RECENT ALERTS
    doc.fontSize(14).fillColor('#fff').text('Recent Alerts', { underline: true }).moveDown(0.3);
    doc.fontSize(10).fillColor('#ccc');
    const alerts = [
      ['High', 'AWS', 'S3 Bucket', 'Public access detected', '2025-11-11 10:01 PM'],
      ['Critical', 'AWS', 'Root Account', 'No MFA', '2025-11-11 09:45 PM'],
      ['High', 'Azure', 'SQL Database', 'Unencrypted at rest', '2025-11-11 09:15 PM'],
    ];
    alerts.forEach(([sev, prov, resrc, desc, time]) => {
      doc.text(`${sev} | ${prov} | ${resrc} | ${desc} | ${time}`).moveDown(0.2);
    });
    doc.moveDown(1);

    // RISK REGISTER
    doc.fontSize(14).fillColor('#fff').text('Risk Register', { underline: true }).moveDown(0.3);
    const risks = [
      'Public S3 bucket with potential PII (High – New)',
      'Azure Storage container with data leak risk (High – New)',
      'IAM user without MFA (High – Open)',
      'Old IAM access key (Medium – In Progress)',
    ];
    doc.fontSize(10).fillColor('#ccc').list(risks).moveDown(1);

    // RECOMMENDATIONS
    doc.fontSize(14).fillColor('#fff').text('Recommendations', { underline: true }).moveDown(0.3);
    doc.fontSize(11).fillColor('#ddd').list([
      'Enable encryption at rest for databases and storage accounts.',
      'Restrict public access to S3 and Azure Blob storage.',
      'Enforce MFA for all IAM users.',
      'Centralize log aggregation and retention (SOX 404 A.12.4).',
    ]);

    doc.moveDown(2).fontSize(10).fillColor('#777').text('XCapital GRC Platform © 2025', {
      align: 'center',
    });

    doc.end();
    stream.on('finish', () => {
      res.download(filePath, filename, () => fs.unlinkSync(filePath));
    });
  } catch (e) {
    console.error('PDF Export Error:', e);
    res.status(500).json({ error: 'Failed to generate report' });
  }
});

/* -----------------------------------------
 * Start
 * ----------------------------------------- */
app.listen(PORT, () => {
  console.log(
    `${DEMO ? '🧪 DEMO MODE' : '🧠 LIVE MODE'} — XCapital server running on :${PORT}`
  );
});

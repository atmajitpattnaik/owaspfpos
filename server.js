const express = require('express');
const multer = require('multer');
const cheerio = require('cheerio');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;

// Configure multer for file uploads
const upload = multer({ dest: 'uploads/' });

// Middleware
app.use(express.json());
app.use(express.static('public'));

// Ensure uploads directory exists
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

/**
 * Convert package.json format to dependencies.json format
 */
function convertPackageJsonToDependencies(packageJson) {
  const dependencies = [];
  
  // Process dependencies
  if (packageJson.dependencies) {
    Object.keys(packageJson.dependencies).forEach(name => {
      const version = packageJson.dependencies[name].replace(/^[\^~]/, ''); // Remove ^ or ~
      dependencies.push({
        name: name,
        version: version,
        children: []
      });
    });
  }
  
  // Process devDependencies (optional, but include them)
  if (packageJson.devDependencies) {
    Object.keys(packageJson.devDependencies).forEach(name => {
      const version = packageJson.devDependencies[name].replace(/^[\^~]/, '');
      dependencies.push({
        name: name,
        version: version,
        children: []
      });
    });
  }
  
  return { dependencies };
}

/**
 * Parse OWASP HTML report to extract dependency vulnerabilities
 */
function parseOWASPReport(htmlContent) {
  const $ = cheerio.load(htmlContent);
  const findings = [];
  const seenDeps = new Set(); // To avoid duplicates

  // Method 1: Parse from summaryTable (real OWASP Dependency-Check format)
  $('#summaryTable tbody tr').each((index, element) => {
    const $row = $(element);
    const cells = $row.find('td');
    
    if (cells.length >= 1) {
      // OWASP reports typically have: Dependency Name, Version, CVEs
      // The dependency name might be in the first cell, possibly with a link
      const firstCell = $(cells[0]);
      let dependencyName = firstCell.text().trim();
      
      // Try to extract from link if present
      const link = firstCell.find('a');
      if (link.length > 0) {
        dependencyName = link.text().trim() || dependencyName;
      }
      
      // Skip header rows
      if (dependencyName.toLowerCase().includes('dependency') || 
          dependencyName.toLowerCase().includes('name') ||
          dependencyName.length === 0) {
        return;
      }
      
      // Version might be in second cell or embedded in dependency name
      let version = '';
      if (cells.length >= 2) {
        version = $(cells[1]).text().trim();
      }
      
      // Extract version from dependency name if format is "name:version"
      if (dependencyName.includes(':')) {
        const parts = dependencyName.split(':');
        dependencyName = parts[0].trim();
        if (parts.length > 1 && !version) {
          version = parts.slice(1).join(':').trim();
        }
      }
      
      // CVE might be in a later cell
      let cve = 'N/A';
      if (cells.length >= 3) {
        cve = $(cells[2]).text().trim() || 'N/A';
      }
      
      if (dependencyName && dependencyName.length > 0) {
        const key = `${dependencyName.toLowerCase()}:${version}`;
        if (!seenDeps.has(key)) {
          seenDeps.add(key);
          findings.push({
            dependencyName: dependencyName,
            version: version || 'unknown',
            cve: cve
          });
        }
      }
    }
  });

  // Method 1b: Parse from dependency sections (h3 tags with dependency names)
  if (findings.length === 0) {
    $('h3, h4').each((index, element) => {
      const $el = $(element);
      const text = $el.text().trim();
      
      // Look for patterns like "dependency-name:version" or dependency names
      // OWASP reports often have dependency names in headers
      if (text && text.length > 0 && !text.toLowerCase().includes('evidence') && 
          !text.toLowerCase().includes('vulnerability') && 
          !text.toLowerCase().includes('header')) {
        // Try to extract dependency name and version
        const patterns = [
          /^([a-zA-Z0-9\-_\.]+):\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?[^\s]*)/,
          /^([a-zA-Z0-9\-_\.]+)\s+\(([0-9]+\.[0-9]+(?:\.[0-9]+)?[^\s]*)\)/,
          /^([a-zA-Z0-9\-_\.]+)\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?[^\s]*)/
        ];
        
        for (const pattern of patterns) {
          const match = text.match(pattern);
          if (match) {
            const depName = match[1].trim();
            const depVersion = match[2].trim();
            const key = `${depName.toLowerCase()}:${depVersion}`;
            
            if (!seenDeps.has(key) && depName.length > 0) {
              seenDeps.add(key);
              findings.push({
                dependencyName: depName,
                version: depVersion,
                cve: 'N/A'
              });
              break;
            }
          }
        }
      }
    });
  }

  // Method 2: Parse from other tables (fallback)
  // Skip header rows by checking if first cell looks like a header
  if (findings.length === 0) {
    $('table tbody tr, table tr').each((index, element) => {
    const $row = $(element);
    const cells = $row.find('td');
    
    // Skip if no cells or if it looks like a header row (th cells or header text)
    if (cells.length === 0 || $row.find('th').length > 0) {
      return;
    }
    
    if (cells.length >= 2) {
      // Try different column arrangements
      let dependencyText = '';
      let versionText = '';
      let cveText = '';
      
      // Common formats:
      // Format 1: [Dependency] [Version] [CVE]
      // Format 2: [Dependency:Version] [CVE]
      // Format 3: [Dependency] [CVE] [Version]
      
      dependencyText = $(cells[0]).text().trim();
      
      // Skip if this looks like a header row
      if (dependencyText.toLowerCase().includes('dependency') || 
          dependencyText.toLowerCase().includes('version') ||
          dependencyText.toLowerCase().includes('cve')) {
        return;
      }
      
      if (cells.length >= 2) {
        versionText = $(cells[1]).text().trim();
      }
      if (cells.length >= 3) {
        cveText = $(cells[2]).text().trim();
      }
      
      // Parse dependency name and version
      let dependencyName = dependencyText;
      let version = versionText;
      
      // Check if dependency text contains version (format: "name:version" or "name (version)")
      if (dependencyText.includes(':')) {
        const parts = dependencyText.split(':');
        dependencyName = parts[0].trim();
        if (parts.length > 1) {
          version = parts.slice(1).join(':').trim();
        }
      } else if (dependencyText.includes('(') && dependencyText.includes(')')) {
        const match = dependencyText.match(/^(.+?)\s*\(([^)]+)\)/);
        if (match) {
          dependencyName = match[1].trim();
          version = match[2].trim();
        }
      }
      
      // If version column exists and is different, use it
      if (versionText && versionText !== dependencyText && !versionText.match(/CVE/i)) {
        version = versionText;
      }
      
      // Clean up dependency name (remove version if still present)
      dependencyName = dependencyName.replace(/[:\s]+v?[\d.]+.*$/, '').trim();
      
      if (dependencyName && dependencyName.length > 0 && dependencyName !== 'unknown') {
        const key = `${dependencyName.toLowerCase()}:${version}`;
        if (!seenDeps.has(key)) {
          seenDeps.add(key);
          findings.push({
            dependencyName: dependencyName,
            version: version || 'unknown',
            cve: cveText || 'N/A'
          });
        }
      }
    }
    });
  }

  // Method 2: Look for dependency-check specific classes and data attributes
  if (findings.length === 0) {
    $('.dependency, .vulnerability, [data-dependency], [class*="dependency"], [class*="vulnerability"]').each((index, element) => {
      const $el = $(element);
      const name = $el.attr('data-name') || 
                   $el.attr('data-dependency') ||
                   $el.find('.name, .dependency-name, [class*="name"]').first().text().trim() ||
                   $el.text().trim();
      
      const version = $el.attr('data-version') || 
                      $el.find('.version, .dependency-version, [class*="version"]').first().text().trim();
      
      const cve = $el.attr('data-cve') || 
                  $el.find('.cve, .vulnerability-id, [class*="cve"]').first().text().trim();
      
      if (name && name.length > 0) {
        const key = `${name.toLowerCase()}:${version}`;
        if (!seenDeps.has(key)) {
          seenDeps.add(key);
          findings.push({
            dependencyName: name,
            version: version || 'unknown',
            cve: cve || 'N/A'
          });
        }
      }
    });
  }

  // Method 3: Parse from list items or divs with dependency info
  if (findings.length === 0) {
    $('li, div').each((index, element) => {
      const $el = $(element);
      const text = $el.text().trim();
      
      // Look for patterns: "dependency:version" or "dependency (version)"
      const patterns = [
        /^([a-zA-Z0-9\-_\.]+):\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?[^\s]*)/,
        /^([a-zA-Z0-9\-_\.]+)\s+\(([0-9]+\.[0-9]+(?:\.[0-9]+)?[^\s]*)\)/,
        /^([a-zA-Z0-9\-_\.]+)\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?[^\s]*)/
      ];
      
      for (const pattern of patterns) {
        const match = text.match(pattern);
        if (match) {
          const depName = match[1].trim();
          const depVersion = match[2].trim();
          const key = `${depName.toLowerCase()}:${depVersion}`;
          
          if (!seenDeps.has(key) && depName.length > 0) {
            seenDeps.add(key);
            findings.push({
              dependencyName: depName,
              version: depVersion,
              cve: 'N/A'
            });
            break;
          }
        }
      }
    });
  }

  // Method 4: Fallback - parse from entire body text
  if (findings.length === 0) {
    const text = $('body').text();
    // Look for patterns like "dependency:version" or "dependency (version)"
    const regex = /([a-zA-Z0-9\-_\.]+)[:\s(]+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?[^\s\)]*)/g;
    let match;
    while ((match = regex.exec(text)) !== null) {
      const depName = match[1].trim();
      const depVersion = match[2].trim();
      const key = `${depName.toLowerCase()}:${depVersion}`;
      
      if (!seenDeps.has(key) && depName.length > 2) {
        seenDeps.add(key);
        findings.push({
          dependencyName: depName,
          version: depVersion,
          cve: 'N/A'
        });
      }
    }
  }

  return findings;
}

/**
 * Recursively extract all dependencies from the dependency tree
 * Helper function to process a single dependency and its children
 */
function processDependency(dep, isTopLevel, allDeps) {
  // Add as direct dependency if top-level
  if (isTopLevel) {
    allDeps.direct.push({
      name: dep.name,
      version: dep.version || 'unknown',
      parent: null
    });
  }

  // Process children (nested dependencies)
  if (dep.children && Array.isArray(dep.children)) {
    dep.children.forEach(child => {
      // Add child as nested dependency
      allDeps.nested.push({
        name: child.name,
        version: child.version || 'unknown',
        parent: dep.name
      });

      // Recursively process this child's children
      processDependency(child, false, allDeps);
    });
  }
}

/**
 * Recursively extract all dependencies from the dependency tree
 */
function extractAllDependencies(dependencyTree) {
  const allDeps = {
    direct: [],
    nested: []
  };

  if (!dependencyTree || !dependencyTree.dependencies) {
    return allDeps;
  }

  // Process each top-level dependency
  dependencyTree.dependencies.forEach(dep => {
    processDependency(dep, true, allDeps);
  });

  return allDeps;
}

/**
 * Normalize version strings for comparison
 */
function normalizeVersion(version) {
  if (!version) return '';
  // Remove leading/trailing whitespace and common prefixes
  return version.toString().trim().replace(/^v/i, '').toLowerCase();
}

/**
 * Check if versions match (allowing for minor differences)
 */
function versionsMatch(version1, version2) {
  const v1 = normalizeVersion(version1);
  const v2 = normalizeVersion(version2);
  
  // Exact match
  if (v1 === v2) return true;
  
  // Try to match major.minor.patch ignoring build metadata
  const v1Clean = v1.split('-')[0].split('+')[0];
  const v2Clean = v2.split('-')[0].split('+')[0];
  
  return v1Clean === v2Clean;
}

/**
 * Main analysis function
 */
function analyzeFalsePositives(owaspFindings, dependencyTree) {
  const allDeps = extractAllDependencies(dependencyTree);
  const falsePositives = {
    directDependencies: [],
    nestedLibraries: []
  };

  // Debug: Log extracted dependencies
  console.log('Direct dependencies:', allDeps.direct.map(d => `${d.name}:${d.version}`));
  console.log('Nested dependencies:', allDeps.nested.map(d => `${d.name}:${d.version} (parent: ${d.parent})`));

  // Create lookup maps for faster searching
  const directDepsMap = new Map();
  allDeps.direct.forEach(dep => {
    const key = dep.name.toLowerCase();
    if (!directDepsMap.has(key)) {
      directDepsMap.set(key, []);
    }
    directDepsMap.get(key).push(dep);
  });

  const nestedDepsMap = new Map();
  allDeps.nested.forEach(dep => {
    const key = dep.name.toLowerCase();
    if (!nestedDepsMap.has(key)) {
      nestedDepsMap.set(key, []);
    }
    nestedDepsMap.get(key).push(dep);
  });

  // Check each OWASP finding
  owaspFindings.forEach(finding => {
    const findingName = finding.dependencyName.toLowerCase();
    const findingVersion = finding.version;

    // Check in direct dependencies
    if (directDepsMap.has(findingName)) {
      const matchingDeps = directDepsMap.get(findingName);
      const versionMatch = matchingDeps.some(dep => versionsMatch(dep.version, findingVersion));
      
      if (!versionMatch) {
        falsePositives.directDependencies.push({
          dependencyName: finding.dependencyName,
          reportedVersion: findingVersion,
          actualVersions: matchingDeps.map(d => d.version),
          reason: `Version mismatch. Found versions: ${matchingDeps.map(d => d.version).join(', ')}`
        });
      }
    } else if (nestedDepsMap.has(findingName)) {
      // Check in nested dependencies
      const matchingDeps = nestedDepsMap.get(findingName);
      const versionMatch = matchingDeps.some(dep => versionsMatch(dep.version, findingVersion));
      
      if (!versionMatch) {
        falsePositives.nestedLibraries.push({
          libraryName: finding.dependencyName,
          reportedVersion: findingVersion,
          actualVersions: matchingDeps.map(d => d.version),
          parentDependency: matchingDeps[0].parent,
          reason: `Version mismatch. Found versions: ${matchingDeps.map(d => d.version).join(', ')}`
        });
      }
    } else {
      // Not found in either direct or nested - definitely a false positive
      // Try to determine if it should be direct or nested based on common patterns
      // For now, we'll add it to direct dependencies
      falsePositives.directDependencies.push({
        dependencyName: finding.dependencyName,
        reportedVersion: findingVersion,
        reason: 'Not found in project dependencies'
      });
    }
  });

  return falsePositives;
}

// API endpoint to analyze files
app.post('/api/analyze', upload.fields([
  { name: 'owaspReport', maxCount: 1 },
  { name: 'dependencies', maxCount: 1 }
]), (req, res) => {
  try {
    if (!req.files || !req.files.owaspReport || !req.files.dependencies) {
      return res.status(400).json({ error: 'Both OWASP report and dependencies.json files are required' });
    }

    // Read and parse OWASP HTML report
    const owaspReportPath = req.files.owaspReport[0].path;
    const owaspHtmlContent = fs.readFileSync(owaspReportPath, 'utf-8');
    const owaspFindings = parseOWASPReport(owaspHtmlContent);

    // Read and parse dependencies.json
    const dependenciesPath = req.files.dependencies[0].path;
    const dependenciesContent = fs.readFileSync(dependenciesPath, 'utf-8');
    let dependencyTree = JSON.parse(dependenciesContent);
    
    // Check if it's a package.json format and convert it
    if (dependencyTree.dependencies && typeof dependencyTree.dependencies === 'object' && !Array.isArray(dependencyTree.dependencies)) {
      // This is a package.json format, convert it
      dependencyTree = convertPackageJsonToDependencies(dependencyTree);
    }

    // Debug logging
    console.log('OWASP Findings:', JSON.stringify(owaspFindings, null, 2));
    
    // Analyze false positives
    const falsePositives = analyzeFalsePositives(owaspFindings, dependencyTree);

    // Debug logging
    console.log('False Positives:', JSON.stringify(falsePositives, null, 2));

    // Clean up uploaded files
    fs.unlinkSync(owaspReportPath);
    fs.unlinkSync(dependenciesPath);

    // Return results
    res.json({
      success: true,
      falsePositives: falsePositives,
      summary: {
        totalOWASPFindings: owaspFindings.length,
        directFalsePositives: falsePositives.directDependencies.length,
        nestedFalsePositives: falsePositives.nestedLibraries.length
      }
    });

  } catch (error) {
    console.error('Error analyzing files:', error);
    res.status(500).json({ 
      error: 'Failed to analyze files', 
      message: error.message 
    });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});


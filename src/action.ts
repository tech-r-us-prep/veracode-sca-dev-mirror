#!/usr/bin/env node

import * as core from '@actions/core'
import { Options } from "./options";
import {runAction, generateVulnList} from './srcclr';


const options: Options = {
    quick: core.getBooleanInput('quick'),
    updateAdvisor: core.getBooleanInput('update_advisor'),
    minCVSSForIssue: parseFloat(core.getInput('min-cvss-for-issue')) || 0,
    url: core.getInput('url'),
    github_token: core.getInput('github_token',{required:true}),
    createIssues: core.getBooleanInput('create-issues'),
    jsonOutput: core.getBooleanInput('json-output'),
    allowDirty: core.getBooleanInput('allow-dirty'),
    failOnCVSS: parseFloat(core.getInput('fail-on-cvss')) || 10,
    path: core.getInput('path',{trimWhitespace: true}) || '.',
    debug: core.getBooleanInput('debug'),
    "skip-vms": core.getBooleanInput('skip-vms'),
    "no-graphs": core.getBooleanInput('no-graphs'),
    recursive: core.getBooleanInput('recursive'),
    "skip-collectors": core.getInput('skip-collectors').split(','),
    "scan-collectors": core.getInput('scan-collectors').split(','),
    platformType: core.getInput('platformType'),
    breakBuildOnPolicyFindings: core.getInput('breakBuildOnPolicyFindings'),
    scaFixEnabled: core.getBooleanInput('sca_fix_enabled'),
    profileName: core.getInput('profile_name'),
    prNumber: core.getInput('pr_number'),
    clientRepositoryBranch: core.getInput('client_repository_branch'),
    clientRepositoryName: core.getInput('client_repository_name'),
    clientRepositoryOwner: core.getInput('client_repository_owner'),
    clientRepositoryFullName: core.getInput('client_repository_full_name')
}

try {
    runAction(options);
    // Only generate vulnerability list for JSON scans when sca-fix is enabled
    if (options.jsonOutput && options.scaFixEnabled) {
        generateVulnList(options);
    }
} catch (error) {
    core.setFailed(error instanceof Error ? error.message : String(error));
}
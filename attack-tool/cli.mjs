#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import guardrailPackage from '../guardrail/src/index.js';
import { createAttackTool } from './server.mjs';
import { createTemplateCatalog } from './template-catalog.mjs';

try {
  const { values } = parseArgs({ options: { config: { type: 'string' } } });
  if (!values.config) throw new Error('usage: node attack-tool/cli.mjs --config <private-config.json>');
  const config = JSON.parse(await readFile(values.config, 'utf8'));
  if (!Array.isArray(config.agents) || !config.agents.length) throw new Error('Configure at least one agent.');
  if (config.agents.some(agent => typeof agent.token !== 'string' || agent.token.length < 32)) {
    throw new Error('Every agent requires a private token of at least 32 characters.');
  }
  const daemon = await createAttackTool({ host: config.host ?? '127.0.0.1', ports: config.ports ?? [4241, 4242],
    ...(config.templateCatalogPath ? { catalog: createTemplateCatalog({ filePath: config.templateCatalogPath }) } : {}),
    principals: config.agents.map(agent => ({ agentId: agent.agentId, runId: agent.runId,
      token: agent.token, portIndex: agent.portIndex,
      guardrail: guardrailPackage.createAttackToolGuardrail({ targetOrigin: agent.targetOrigin,
        maxRequests: agent.maxRequests ?? 16, allowedPaths: agent.allowedPaths ?? ['/api/search'] }) })) });
  console.log(JSON.stringify({ service: 'attack-tool', endpoints: daemon.endpoints }));
  const stop = async () => { await daemon.close(); };
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
} catch (error) {
  console.error(JSON.stringify({ error: { message: error.message } }));
  process.exitCode = 1;
}

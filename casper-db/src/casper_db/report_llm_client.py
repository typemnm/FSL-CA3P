"""Direct local Ollama transport. No proxies, redirects, cloud fallback or body logs."""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import socket
from urllib.parse import urlsplit

VERSION = 'local-report-llm-1'
MAX_RESPONSE = 1_000_000


def generation_schema(schema):
    """Keep the generation grammar small; enforce all bounds with Pydantic after it."""
    limits = {'title', 'minLength', 'maxLength',
              'minimum', 'maximum', 'pattern'}
    if isinstance(schema, dict):
        return {key: generation_schema(value) for key, value in schema.items() if key not in limits}
    if isinstance(schema, list):
        return [generation_schema(value) for value in schema]
    return schema


class LocalLlmError(ValueError):
    """Messages never include a prompt, model response, credentials or report text."""


def endpoint_address(value):
    parsed = urlsplit(value)
    if (parsed.scheme != 'http' or parsed.username or parsed.password or parsed.query
            or parsed.fragment or parsed.path not in ('', '/')):
        raise LocalLlmError('local LLM requires a direct local HTTP endpoint')
    host = parsed.hostname
    if host not in {'localhost', '127.0.0.1', '::1', 'report-llm'}:
        raise LocalLlmError('external LLM endpoints are forbidden for report extraction')
    try:
        port = parsed.port or 11434
        addresses = sorted({entry[4][0] for entry in socket.getaddrinfo(
            host, port, type=socket.SOCK_STREAM
        )})
    except (ValueError, OSError) as exc:
        raise LocalLlmError('local LLM address is unavailable') from exc
    if not addresses:
        raise LocalLlmError('local LLM address is unavailable')
    subnet = ipaddress.ip_network(os.environ.get('CASPER_DB_REPORT_LLM_SUBNET',
                                                '172.29.120.0/24'))
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not (ip.is_loopback if host != 'report-llm' else ip in subnet and ip.is_private):
            raise LocalLlmError('local LLM address escaped the permitted local network')
    return addresses[0], port, host


class LocalReportLlm:
    def __init__(self, *, endpoint=None, model=None, timeout=180):
        self.endpoint = endpoint or os.environ.get('CASPER_DB_REPORT_LLM_URL', '')
        self.model = model or os.environ.get('CASPER_DB_REPORT_LLM_MODEL',
                                            'qwen3-vl:8b-instruct')
        if not self.endpoint:
            raise LocalLlmError('local report LLM is not configured')
        if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,160}', self.model)
                or 'cloud' in self.model.lower()):
            raise LocalLlmError('a locally installed model is required')
        self.address, self.port, self.host = endpoint_address(self.endpoint)
        self.timeout = min(max(timeout, 1), 300)
        self.digest = None
        self.metrics = []

    def request(self, method, path, body=None, *, timeout=None):
        # http.client does not consume HTTP_PROXY/HTTPS_PROXY/ALL_PROXY and cannot
        # follow a redirect. Resolve once and connect to that exact local address.
        connection = http.client.HTTPConnection(self.address, self.port,
                                                timeout=timeout or self.timeout)
        try:
            encoded = json.dumps(body, ensure_ascii=False).encode() if body is not None else None
            connection.request(method, path, encoded, headers={
                'Content-Type': 'application/json', 'Host': f'{self.host}:{self.port}',
            })
            response = connection.getresponse()
            if response.status != 200:
                # Classify errors locally without exposing a response that could
                # echo private document data.
                error_body = response.read(8192).decode('utf-8', errors='replace').lower()
                category = next((label for word, label in (
                    ('image', 'image_input'), ('schema', 'output_schema'),
                    ('thinking', 'thinking_option'), ('context', 'context_limit'),
                ) if word in error_body), 'request_rejected')
                raise LocalLlmError(f'local LLM returned HTTP {response.status} ({category})')
            raw = response.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE:
                raise LocalLlmError('local LLM response exceeded its limit')
            return json.loads(raw)
        except LocalLlmError:
            raise
        except (OSError, ValueError, http.client.HTTPException) as exc:
            raise LocalLlmError('local LLM request failed or timed out') from exc
        finally:
            connection.close()

    def check(self):
        tags = self.request('GET', '/api/tags', timeout=3)
        record = next((item for item in tags.get('models', [])
                       if item.get('name') == self.model or item.get('model') == self.model), None)
        if (not record or record.get('remote_model') or record.get('remote_host')
                or not re.fullmatch(r'(?:sha256:)?[a-f0-9]{64}', record.get('digest', ''))):
            raise LocalLlmError('configured model is not installed locally')
        info = self.request('POST', '/api/show', {'model': self.model}, timeout=5)
        if info.get('remote_model') or info.get('remote_host'):
            raise LocalLlmError('cloud models are forbidden for report extraction')
        if 'vision' not in info.get('capabilities', []):
            raise LocalLlmError('report extraction requires a local vision model')
        self.digest = record['digest']
        return {'available': True, 'model': self.model, 'digest': self.digest,
                'transport': 'direct-local-http', 'cloud_fallback': False}

    def chat(self, *, system, content, schema, images=()):
        if self.digest is None:
            self.check()
        result = self.request('POST', '/api/chat', {
            'model': self.model, 'stream': False, 'think': False, 'keep_alive': '10m',
            'messages': [{'role': 'system', 'content': system},
                         {'role': 'user', 'content': content, 'images': list(images)}],
            'format': generation_schema(schema),
            'options': {'temperature': 0, 'seed': 42, 'num_ctx': 32768, 'num_predict': 6144},
        })
        self.metrics.append({key: result.get(key) for key in
                             ('done_reason', 'prompt_eval_count', 'eval_count', 'total_duration')})
        if result.get('done_reason') == 'length':
            raise LocalLlmError('local LLM output reached its token limit')
        if result.get('prompt_eval_count', 0) >= 31744:
            raise LocalLlmError('local LLM context limit reached; split this finding')
        if result.get('model') != self.model or result.get('message', {}).get('tool_calls'):
            raise LocalLlmError('unexpected model response')
        try:
            return json.loads(result['message']['content'])
        except (ValueError, KeyError, TypeError):
            raise LocalLlmError('local LLM did not return structured data') from None


def local_llm_status():
    if not os.environ.get('CASPER_DB_REPORT_LLM_URL'):
        return {'configured': False, 'available': False, 'cloud_fallback': False}
    try:
        return {'configured': True, **LocalReportLlm(timeout=3).check()}
    except LocalLlmError as exc:
        return {'configured': True, 'available': False, 'reason': str(exc),
                'cloud_fallback': False}

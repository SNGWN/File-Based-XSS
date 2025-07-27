# PDF XSS Payload Generator

![Last Updated](https://img.shields.io/badge/Last%20Updated-2025--07--27-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Python](https://img.shields.io/badge/Python-3.7%2B-blue)

A comprehensive tool for generating PDF-based XSS (Cross-Site Scripting) payloads that target various browsers and PDF rendering engines. These payloads focus on accessing the browser DOM, file system access, and command execution capabilities by escaping sandbox protections.

**Author:** SNGWN  
**Last Updated:** 2025-07-27 06:04:52 UTC

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Payload Categories](#payload-categories)
- [Browser Compatibility](#browser-compatibility)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [References](#references)
- [Disclaimer](#disclaimer)

## Overview

This tool generates over 100 distinct PDF XSS payloads targeting various browsers and PDF rendering engines. Each payload is carefully crafted to exploit specific behaviors or vulnerabilities in different PDF renderers, potentially allowing access to browser DOM, file system operations, or command execution by escaping sandboxes.

## Features

- 100+ unique PDF XSS payloads
- Browser-specific targeting (Chrome, Firefox, Safari)
- PDF renderer-specific payloads (PDF.js, Adobe Reader)
- Custom URL integration for data exfiltration
- Organized output by browser/renderer type
- Detailed payload descriptions

## Installation

1. Clone the repository:
```bash
git clone https://github.com/SNGWN/pdf-xss-generator.git
cd pdf-xss-generator

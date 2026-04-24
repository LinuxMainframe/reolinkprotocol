# Baichuan Connection Layer

This Python module provides a dedicated interface for interacting with the proprietary Baichuan protocol used by Reolink camera systems. It is designed as a foundational library for authorization and media streaming.

## Overview

The Baichuan protocol is an ARM-based communication system that manages device authentication and media transport. This implementation serves as a modern, documented alternative to existing tools like NeoLink, focusing on reliability and codebase clarity.

## Key Features

* Full session management including login and keep-alive heartbeats.
* Direct interaction with the Baichuan SoC command structure.
* Stream request handling for main and sub-stream types.
* Low-level frame parsing for media packets.
* Extensive logging and error handling for connection stability.

## Requirements

* Python 3.x
* Socket access to a compatible Reolink/Baichuan device.

## Usage

The module can be used to establish a session and capture raw media frames.

```python
from ConnectionLayer import BaichuanClient

# Initialize the client
bc = BaichuanClient(host="192.168.1.100", port=9000)

# Authenticate and start a stream
if bc.login(username="admin", password="password"):
    streaming = bc.request_stream(channel_id=0, stream_type="mainStream")
    
    if streaming:
        # Process incoming frames
        while True:
            frame = bc.recv_frame()
            if not frame:
                break
            # Handle frame data
```

## Background

This project builds upon reverse-engineering efforts by the community to address limitations found in standard RTSP or RTMP implementations, such as artifacting and buffer issues. It aims to provide a more robust way to integrate Reolink cameras into custom Python-based video processing pipelines.

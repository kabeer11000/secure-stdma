/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2025 Secure STDMA Project
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 */

#include "stdma-neighbor-cache.h"
#include "ns3/log.h"
#include "ns3/simulator.h"

NS_LOG_COMPONENT_DEFINE("stdma.NeighborCache");

namespace stdma {

using ns3::TypeId;
using ns3::Object;
using ns3::Simulator;

NS_OBJECT_ENSURE_REGISTERED(NeighborCache);

TypeId
NeighborCache::GetTypeId(void) {
    static TypeId tid = TypeId("stdma::NeighborCache")
        .SetParent<Object>()
        .AddConstructor<NeighborCache>()
        .SetGroupName("stdma");
    return tid;
}

NeighborCache::NeighborCache() {}
NeighborCache::~NeighborCache() {}

void
NeighborCache::AddKey(ns3::Mac48Address nodeId, const std::vector<uint8_t>& publicKey) {
    NeighborEntry& entry = m_cache[nodeId];
    entry.nodeId = nodeId;
    entry.publicKey = publicKey;
    entry.keyVerified = false;
    if (entry.lastSeqNum == 0) {
        entry.lastSeqNum = 0;
    }
    entry.lastSeen = ns3::Simulator::Now();
}

bool
NeighborCache::HasKey(ns3::Mac48Address nodeId) const {
    return m_cache.find(nodeId) != m_cache.end();
}

std::vector<uint8_t>
NeighborCache::GetKey(ns3::Mac48Address nodeId) const {
    auto it = m_cache.find(nodeId);
    if (it == m_cache.end()) {
        return std::vector<uint8_t>();
    }
    return it->second.publicKey;
}

bool
NeighborCache::ValidateSeqNum(ns3::Mac48Address nodeId, uint32_t seqNum) {
    auto it = m_cache.find(nodeId);
    if (it == m_cache.end()) {
        NS_LOG_WARN("No cached entry for node " << nodeId << " - possible late joiner");
        return false;
    }
    if (seqNum <= it->second.lastSeqNum) {
        NS_LOG_WARN("Replay attack detected from " << nodeId
                   << ": seq=" << seqNum << " <= lastSeq=" << it->second.lastSeqNum);
        return false;
    }
    return true;
}

void
NeighborCache::UpdateSeqNum(ns3::Mac48Address nodeId, uint32_t seqNum) {
    auto it = m_cache.find(nodeId);
    if (it != m_cache.end()) {
        it->second.lastSeqNum = seqNum;
        it->second.lastSeen = ns3::Simulator::Now();
    }
}

uint32_t
NeighborCache::GetLastSeqNum(ns3::Mac48Address nodeId) const {
    auto it = m_cache.find(nodeId);
    if (it == m_cache.end()) {
        return 0;
    }
    return it->second.lastSeqNum;
}

bool
NeighborCache::IsKeyVerified(ns3::Mac48Address nodeId) const {
    auto it = m_cache.find(nodeId);
    if (it == m_cache.end()) {
        return false;
    }
    return it->second.keyVerified;
}

void
NeighborCache::MarkKeyVerified(ns3::Mac48Address nodeId) {
    auto it = m_cache.find(nodeId);
    if (it != m_cache.end()) {
        it->second.keyVerified = true;
    }
}

void
NeighborCache::Remove(ns3::Mac48Address nodeId) {
    m_cache.erase(nodeId);
}

void
NeighborCache::Clear() {
    m_cache.clear();
}

uint32_t
NeighborCache::GetSize() const {
    return static_cast<uint32_t>(m_cache.size());
}

} // namespace stdma

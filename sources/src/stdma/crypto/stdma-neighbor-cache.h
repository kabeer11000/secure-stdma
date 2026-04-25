/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2025 Secure STDMA Project
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 */

#ifndef STDMA_NEIGHBOR_CACHE_H
#define STDMA_NEIGHBOR_CACHE_H

#include "ns3/object.h"
#include "ns3/mac48-address.h"
#include "ns3/nstime.h"
#include <map>

namespace stdma {

/**
 * \brief Cached information about a verified peer node
 */
struct NeighborEntry {
    /** The node's MAC address */
    ns3::Mac48Address nodeId;
    /** Verified public key bytes (64 bytes for P-256) */
    std::vector<uint8_t> publicKey;
    /** Last accepted sequence number (for replay protection) */
    uint32_t lastSeqNum;
    /** Timestamp of last received packet */
    ns3::Time lastSeen;
    /** Whether the key has been verified against CA */
    bool keyVerified;
};

/**
 * \brief Cache of verified peer public keys and sequence numbers
 *
 * Maintains state for replay attack protection and late-joiner detection.
 * Each node maintains one entry per observed peer.
 */
class NeighborCache : public ns3::Object {
public:
    static ns3::TypeId GetTypeId(void);

    NeighborCache();
    virtual ~NeighborCache();

    /**
     * Add or update a peer's public key
     */
    void AddKey(ns3::Mac48Address nodeId, const std::vector<uint8_t>& publicKey);

    /**
     * Check if we have a verified key for this peer
     */
    bool HasKey(ns3::Mac48Address nodeId) const;

    /**
     * Get the cached public key for a peer
     * Returns empty vector if not found
     */
    std::vector<uint8_t> GetKey(ns3::Mac48Address nodeId) const;

    /**
     * Check if a sequence number is valid (greater than last seen)
     * Returns true if valid, false if replay attack detected
     */
    bool ValidateSeqNum(ns3::Mac48Address nodeId, uint32_t seqNum);

    /**
     * Update the cached sequence number after successful validation
     */
    void UpdateSeqNum(ns3::Mac48Address nodeId, uint32_t seqNum);

    /**
     * Get the last seen sequence number for a peer
     */
    uint32_t GetLastSeqNum(ns3::Mac48Address nodeId) const;

    /**
     * Check if a peer's key has been verified against CA
     */
    bool IsKeyVerified(ns3::Mac48Address nodeId) const;

    /**
     * Mark a peer's key as verified
     */
    void MarkKeyVerified(ns3::Mac48Address nodeId);

    /**
     * Remove a peer from the cache
     */
    void Remove(ns3::Mac48Address nodeId);

    /**
     * Clear all entries
     */
    void Clear();

    /**
     * Get the number of cached entries
     */
    uint32_t GetSize() const;

private:
    std::map<ns3::Mac48Address, NeighborEntry> m_cache;
};

} // namespace stdma

#endif /* STDMA_NEIGHBOR_CACHE_H */

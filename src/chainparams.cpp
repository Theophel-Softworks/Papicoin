// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2022 Papicoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "NY Times 28/Oct/2022 Ukraine President Cautions Against War Talk"; // Oct actually was Jan, but it does not matter for Genesis.
    const CScript genesisOutputScript = CScript() << ParseHex("042384710fa68ad25023690c80f3468c8f13f8daad8c857fb6798bc4a8e4d3eb4b10f4d460adf08dce601aaf0f470b3cfe1ab7770b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 1155801;
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); 
        consensus.nPowTargetTimespan = 5 * 60;
        consensus.nPowTargetSpacing = 1 * 30;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 6048; // 75% of 8064
        consensus.nMinerConfirmationWindow = 8064; // nPowTargetTimespan / nPowTargetSpacing * 4

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xbd;
        pchMessageStart[1] = 0xca;
        pchMessageStart[2] = 0xf6;
        pchMessageStart[3] = 0x2a;
        nDefaultPort = 44774;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1643388629, 2000609473, 0x1e0ffff0, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
		assert(genesis.hashMerkleRoot == uint256S("0x1f0e8d133387e0e6e264a66b2bdbd9670ec0821065ccc189ec164153868f92c2"));
        assert(consensus.hashGenesisBlock == uint256S("0x9129aa2517de90550d450d57be9a9bc2da9c6ed56bc8805cbb71747ccc734a1d"));

        // Note that of those with the service bits flag, most only support a subset of possible options
        vSeeds.push_back(CDNSSeedData("89.58.28.213", "89.58.28.213", true));
        vSeeds.push_back(CDNSSeedData("185.163.118.233", "185.163.118.233", true));
        vSeeds.push_back(CDNSSeedData("188.68.52.16", "188.68.52.16", true));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,55);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,50);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,176);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (  0, uint256S("0x9129aa2517de90550d450d57be9a9bc2da9c6ed56bc8805cbb71747ccc734a1d"))
            (  100, uint256S("0xe5bd71ef221490a87f6c3e9f3316de46445abb38da39e5803817d3d3830874f5"))
            (  200, uint256S("0x67b2f460db93ebaaaeef1f791a5ad85f9e6f6d135028728e0c9eccb8dd0c8a05"))
            (  300, uint256S("0x09abb8a7255d93b973ab69497c4e47946a64ac83aae61035aa9a8be270d792e9"))
            (  400, uint256S("0xcbbb745a9e8ad0a67ce6c4bb65968d1fd72c539d5f3d1f64c6ad7b8fe1575c87"))
            (  500, uint256S("0x07c038e0a83e248c566b77ba23d01d744f3ae040de8971b79f3f9460f880ee79"))
            (  600, uint256S("0x6c2cf5c36b75458bbc60d82e1a67e948448754d2c78e1bea2772a295c1068a35"))
            (  700, uint256S("0xbefce2b2d7d5728e5c6e044c16e323b180e1273d881f591cbb9fb9264d88072a"))
            (  800, uint256S("0xfafa750c584c25784dc09c2d6886f33eb360d472d60b5d83725a2f11812f1207"))
            (  900, uint256S("0xbe3c351f894d804f626bd91074917b9ba3b6628efa9ec5cf8229ae31855ea6d9"))
            (  1000, uint256S("0xbefce2b2d7d5728e5c6e044c16e323b180e1273d881f591cbb9fb9264d88072a"))
        };

        chainTxData = ChainTxData{
            // Data as of block 0x9129aa2517de90550d450d57be9a9bc2da9c6ed56bc8805cbb71747ccc734a1d (height 0).
            1643388629, // * UNIX timestamp of last known number of transactions
            0,  // * total number of transactions between genesis and that timestamp
                    //   (the tx=... number in the SetBestChain debug.log lines)
            0.0     // * estimated number of transactions per second after that timestamp
        };
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 1155801;
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 5 * 60;
        consensus.nPowTargetSpacing = 1 * 30;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing

        pchMessageStart[0] = 0xdf;
        pchMessageStart[1] = 0xfa;
        pchMessageStart[2] = 0xc3;
        pchMessageStart[3] = 0x8a;
        nDefaultPort = 44775;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1643388629, 567095, 0x1e0ffff0, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
		assert(genesis.hashMerkleRoot == uint256S("0x1f0e8d133387e0e6e264a66b2bdbd9670ec0821065ccc189ec164153868f92c2"));
        assert(consensus.hashGenesisBlock == uint256S("0x657c25695adb6efa2aad41289128545356f981c38e098a773b24ff5ff1e5ea8a"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
		vSeeds.push_back(CDNSSeedData("89.58.28.213", "89.58.28.213", true));
        vSeeds.push_back(CDNSSeedData("185.163.118.233", "185.163.118.233", true));
        vSeeds.push_back(CDNSSeedData("188.68.52.16", "188.68.52.16", true));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,117);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,58);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 0, uint256S("0x657c25695adb6efa2aad41289128545356f981c38e098a773b24ff5ff1e5ea8a")),
        };

        chainTxData = ChainTxData{
            // Data as of block 0x657c25695adb6efa2aad41289128545356f981c38e098a773b24ff5ff1e5ea8a (height 0)
            1643388629,
            0,
            0.0
        };

    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 5 * 60;
        consensus.nPowTargetSpacing = 1 * 30;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xbb;
        pchMessageStart[1] = 0xcc;
        pchMessageStart[2] = 0xcb;
        pchMessageStart[3] = 0xdf;
        nDefaultPort = 44776;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1643388629, 0, 0x207fffff, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
		assert(genesis.hashMerkleRoot == uint256S("0x1f0e8d133387e0e6e264a66b2bdbd9670ec0821065ccc189ec164153868f92c2"));
        assert(consensus.hashGenesisBlock == uint256S("0x2204cf542cefda33e8037b854db105fafb92803df6be7c0df4af4eab98ec6068"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true; 

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0x2204cf542cefda33e8037b854db105fafb92803df6be7c0df4af4eab98ec6068"))
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,117);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,58);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}

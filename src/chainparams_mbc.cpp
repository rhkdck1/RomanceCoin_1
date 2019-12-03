// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2019 RomanceCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/merkle.h>

#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>
#include <snapshot.h>
#include <univalue.h>

#include <assert.h>
#include <chainparamsseeds.h>
#include <arith_uint256.h>

void GenesisGenerator(CBlock genesis) {
    printf("Searching for genesis block...\n");

    uint256 hash;
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;
    bnTarget.SetCompact(genesis.nBits, &fNegative, &fOverflow);

    while(true)
    {
        hash = genesis.GetWorkHash();
        if (UintToArith256(hash) <= bnTarget)
            break;
        if ((genesis.nNonce & 0xFFF) == 0)
        {
            printf("nonce %08X: hash = %s (target = %s)\n", genesis.nNonce, hash.ToString().c_str(), bnTarget.ToString().c_str());
        }
        ++genesis.nNonce;
        if (genesis.nNonce == 0)
        {
            printf("NONCE WRAPPED, incrementing time\n");
            ++genesis.nTime;
        }
    }

    printf("block.nNonce = %u \n", genesis.nNonce);
    printf("block.GetIndexHash = %s\n", genesis.GetIndexHash().ToString().c_str());
    printf("block.GetWorkHash = %s\n", genesis.GetWorkHash().ToString().c_str());
    printf("block.MerkleRoot = %s \n", genesis.hashMerkleRoot.ToString().c_str());
}

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward, std::vector<SnapshotEntry> vSnapshot)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(vSnapshot.size() + 1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    int i = 1;
    for (auto const& tx: vSnapshot) {
        txNew.vout[i].nValue = tx.amount;
        txNew.vout[i].scriptPubKey = tx.script;
        i++;
    }

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
 * Build the genesis block. It includes snapshot coins from vSnapshot
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward, const char* pszTimestamp, const char* pszTimestamp, std::vector<SnapshotEntry> vSnapshot)
{
    //const CScript genesisOutputScript = CScript() << ParseHex("0402cf9b6f0ff5ff6ce705a0c7ed563b9d4803f4a6ad74c8f02892ad1d41aae44c03513b19d359d647e293fcf621e30f373c707a1794b1239f70938f661656d59b") << OP_CHECKSIG;
    const CScript genesisOutputScript = CScript() << ParseHex("0453b06d563e89357f0ee60a85d78e842adccd5b47b8fd9f9e77e6a946547f38e2135e5c97fe7b4ae220ddf4b6c54a84158f268cff809503f378c0dce6f0f84791") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward, vSnapshot);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
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
    CMainParams(const ArgsManager& args) {
        strNetworkID = "main";
        consensus.nBIP34Enabled = true;
        consensus.nBIP65Enabled = true;
        consensus.nBIP66Enabled = true;
        consensus.nSegwitEnabled = true;
        consensus.nCSVEnabled = true;
        consensus.powLimit = uint256S("003fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        consensus.lwmaAveragingWindow = 90;
        consensus.baseReward = 5500 * COIN;

        // Decrease reward by 30% each 2 years
        consensus.rewardEpoch = 525960 * 2; 
        consensus.rewardEpochRate = 0.3;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xf1;
        pchMessageStart[1] = 0xc2;
        pchMessageStart[2] = 0xb6;
        pchMessageStart[3] = 0xd2;
        nDefaultPort = 2502;
        nPruneAfterHeight = 100000;

        const char* pszTimestamp = "The WSJ 09/Oct/2019 Nobel Prize in Chemistry Awarded to Developers of Lithium-Ion Batteries";
        std::vector<SnapshotProvider> providers = {
            {"sman.pw", "/snapshot/mainnet.csv", 80}
        };

        //vSnapshot = InitSnapshot("mainnet.csv", providers);
        genesis = CreateGenesisBlock(1574659287, 709, 0x1f3fffff, 1, consensus.baseReward, pszTimestamp);

        
        consensus.hashGenesisBlock = genesis.GetIndexHash();
        consensus.hashGenesisBlockWork = genesis.GetWorkHash();

        GenesisGenerator(genesis);

        printf("consensus.hashGenesisBlock = %s\n", consensus.hashGenesisBlock.ToString().c_str());
        printf("consensus.hashGenesisBlockWork = %s\n", consensus.hashGenesisBlockWork.ToString().c_str());
        printf("genesis.hashMerkleRoot = %s\n", genesis.hashMerkleRoot.ToString().c_str());
        //assert(consensus.hashGenesisBlock == uint256S("0x14c03ecf20edc9887fb98bf34b53809f063fc491e73f588961f764fac88ecbae"));
        assert(consensus.hashGenesisBlock == uint256S("0xa592f7e9b12c9c6034f9e473d2e27b6c73c578306e37f81700e72cc73532379e"));
        assert(consensus.hashGenesisBlockWork == uint256S("0x78cc686a7f13fa063ed525e840b503f74a7cb8081d0f3783f41ce238055ef4af"));
        assert(genesis.hashMerkleRoot == uint256S("0x5293440f56ff872c1ba25f86e5a4fd517476b5d3406539b11868539b0cf8438a"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,60);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,51);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "rmc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {

            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        /* enable fallback fee on mainnet */
        m_fallback_fee_enabled = true;
    }
};

/**
 * Testnet
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams(const ArgsManager& args) {
        strNetworkID = "test";
        consensus.nBIP34Enabled = true;
        consensus.nBIP65Enabled = true;
        consensus.nBIP66Enabled = true;
        consensus.nSegwitEnabled = true;
        consensus.nCSVEnabled = true;
        consensus.powLimit = uint256S("003fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        consensus.lwmaAveragingWindow = 90;
        consensus.baseReward = 5500 * COIN;

        // Decrease reward by 30% each 2 years
        consensus.rewardEpoch = 525960 * 2; 
        consensus.rewardEpochRate = 0.3;

        pchMessageStart[0] = 0xf1;
        pchMessageStart[1] = 0xc2;
        pchMessageStart[2] = 0xb6;
        pchMessageStart[3] = 0xd2;
        nDefaultPort = 12502;
        nPruneAfterHeight = 1000;

        const char* pszTimestamp = "The WSJ 05/Oct/2019 Hong Kong Shuts Down After Night of Violence";
        std::vector<SnapshotProvider> providers = {
            {"sman.pw", "/snapshot/testnet.csv", 80}
        };

        vSnapshot = InitSnapshot("testnet.csv", providers);
        genesis = CreateGenesisBlock(1574659287, 135893, 0x1f3fffff, 1, consensus.baseReward, pszTimestamp, vSnapshot);

        consensus.hashGenesisBlock = genesis.GetIndexHash();
        consensus.hashGenesisBlockWork = genesis.GetWorkHash();

        printf("consensus.hashGenesisBlock = %s\n", consensus.hashGenesisBlock.ToString().c_str());
        printf("consensus.hashGenesisBlockWork = %s\n", consensus.hashGenesisBlockWork.ToString().c_str());
        printf("genesis.hashMerkleRoot = %s\n", genesis.hashMerkleRoot.ToString().c_str());

        assert(consensus.hashGenesisBlock == uint256S("0x9b751493ca843a182ee173ac425f6825d402624eac9637f5b2309029cb3be62c"));
        assert(consensus.hashGenesisBlockWork == uint256S("0xa9907a67ecd2f16a4b2b79808e512099aa7a9f29e68313caa64175e049738550"));
        assert(genesis.hashMerkleRoot == uint256S("0xe4a96722accafc494c78667ca0dd92866ea97498284e4627429bbc870b3d208d"));

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,71);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,73);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "trmc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;


        checkpointData = {
            {

            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        /* enable fallback fee on testnet */
        m_fallback_fee_enabled = true;
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams(const ArgsManager& args) {
        strNetworkID = "regtest";
        consensus.nBIP34Enabled = false;
        consensus.nBIP65Enabled = true;
        consensus.nBIP66Enabled = true;
        consensus.nSegwitEnabled = true;
        consensus.nCSVEnabled = true;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        consensus.lwmaAveragingWindow = 90;
        consensus.baseReward = 5500 * COIN;

        // Decrease reward by 30% each 2 years
        consensus.rewardEpoch = 525960 * 2; 
        consensus.rewardEpochRate = 0.3;

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 22502;
        nPruneAfterHeight = 1000;

        const char* pszTimestamp = "The WSJ 10/Sep/2019 There’s Too Much Negativity About Negative Rates";
        std::vector<SnapshotProvider> providers = {
            {"sman.pw", "/snapshot/regtest.csv", 80}
        };

        vSnapshot = InitSnapshot("regtest.csv", providers);
        genesis = CreateGenesisBlock(1296688602, 11, 0x207fffff, 1, 900 * COIN, pszTimestamp, vSnapshot);
        
        consensus.hashGenesisBlock = genesis.GetIndexHash();
        consensus.hashGenesisBlockWork = genesis.GetWorkHash();

        assert(consensus.hashGenesisBlock == uint256S("0xe1696b8a3aad3447d708dee1caced75d267d517645f18e8cb48e0b96211c823e"));
        assert(consensus.hashGenesisBlockWork == uint256S("0xf675dfa5a06949d6bf6813bb4ea51178be153a272d24f6906ef56790de3eddf3"));
        assert(genesis.hashMerkleRoot == uint256S("0xeee9c2aee9997d25398dfbc9bc3dc45121381381db6b630330855181d44a760d"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
            {

            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "rrmc";

        /* enable fallback fee on regtest */
        m_fallback_fee_enabled = true;
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams(gArgs));
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams(gArgs));
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams(gArgs));
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}
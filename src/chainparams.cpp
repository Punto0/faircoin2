// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"
#include "primitives/block.h"
#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include "key.h"
#include "poc.h"
#include "base58.h"
#include "chainparamsseeds.h"

#include <stdio.h>
#include <assert.h>
#include <boost/assign/list_of.hpp>

CDynamicChainParams dynParams;

// #define SHOW_GENESIS_HASHES 0

#if SHOW_GENESIS_HASHES
#define PRINT_HASHES \
    printf("%s parameters\n" \
            "block hash   : %s\n" \
            "merkle root  : %s\n" \
            "payload hash : %s\n\n", \
            strNetworkID.c_str(), \
            consensus.hashGenesisBlock.ToString().c_str(), \
            genesis.hashMerkleRoot.ToString().c_str(), \
            genesis.hashPayload.ToString().c_str())
#endif

#define GENESIS_BLOCK_TIMESTAMP 1518996845
const char* genesisMessage = "Nac Mac Feegle! The Wee Free Men! Nae king! Nae quin! Nae laird! Nae master! We willna' be fooled again!";

static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nCreatorId, const CDynamicChainParams& dynamicChainParams)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << OP_0 << CScriptNum(GENESIS_NODE_ID) << OP_0; // Serialised block height + genesis node ID + zero
    txNew.vout[0].nValue = 0;
    txNew.vout[0].scriptPubKey = CScript() << OP_RETURN << std::vector<uint8_t>((uint8_t*)genesisMessage, (uint8_t*)genesisMessage + strlen(genesisMessage));

    CBlock genesis;
    genesis.nVersion   = CBlock::CURRENT_VERSION | CBlock::TX_PAYLOAD | CBlock::CVN_PAYLOAD | CBlock::CHAIN_PARAMETERS_PAYLOAD | CBlock::CHAIN_ADMINS_PAYLOAD;
    genesis.nTime      = nTime;
    genesis.nCreatorId = nCreatorId;
    genesis.hashPrevBlock.SetNull();
    genesis.vtx.push_back(txNew);
    genesis.dynamicChainParams = dynamicChainParams;
    return genesis;
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
        /** 
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        vAlertPubKey = ParseHex("04b06af4982ca3edc2c040cc2cde05fa5b33264af4a98712ceb29d196e7390b4753eb7264dc5f383f29a44d63e70dbbd8d9e46a0a60f80ef62fd1911291ec388e4");
        nDefaultPort = 40404;
        nPruneAfterHeight = 100000;

        CDynamicChainParams dynParams;
        dynParams.nBlockSpacing                = 3 * 60; // 3 min.
        dynParams.nBlockSpacingGracePeriod     = 60;
        dynParams.nMaxAdminSigs                = 11;
        dynParams.nMinAdminSigs                = 1;
        dynParams.nTransactionFee              = 0 * CENT; // 0 FAIR per Kb
        dynParams.nDustThreshold               = 0 * CENT; // 0 FAIR
        dynParams.nMinSuccessiveSignatures     = 1;
        dynParams.nBlocksToConsiderForSigCheck = 1;
        dynParams.nPercentageOfSignaturesMean  = 70; // 70%
        dynParams.nMaxBlockSize                = 1500000; // 1.5Mb
        dynParams.nBlockPropagationWaitTime    = 50; // 50 sec.
        dynParams.nRetryNewSigSetInterval      = 15; // 15 sec.
        dynParams.nCoinbaseMaturity            = 10; // 10 blocks = 30 min.
        dynParams.strDescription               = "#00001 https://fair-coin.org/ The genesis dynamic chain parameters";

        genesis = CreateGenesisBlock(GENESIS_BLOCK_TIMESTAMP, GENESIS_NODE_ID, dynParams);

        genesis.vCvns.resize(1);
        genesis.vCvns[0] = CCvnInfo(GENESIS_NODE_ID, 0, CSchnorrPubKeyDER("04f69bd29a5e2b8d0f5c185fcc421d11556c071788de07d3d194ded04721afaa652ad75a649a0dac8f576e484392af68f5c31ab0ef5e3432baf8b14b6ad8b1262c"));

        genesis.vChainAdmins.resize(1);
        genesis.vChainAdmins[0] = CChainAdmin(GENESIS_ADMIN_ID, 0, CSchnorrPubKeyDER("041cbfa5cb7dbe6387c0808264feb7adc9d99a003da4922e839a548955307f3d365f9fe6fa76767e848660ec864c9f3075fdcdf3e3755af9e3c2662004979ff580"));

        genesis.chainMultiSig = CSchnorrSigS("14dc4f77f9d59ece2b3aa02cc4df99954d47fa2719be207d1b5010745aec419e451f01a8749cd16f22a727d0deba5110d2ce7e44ff86f0efdea58db4efdb92cd");
        genesis.vAdminIds.push_back(GENESIS_ADMIN_ID);
        genesis.adminMultiSig = CSchnorrSigS("591039a3b2e2c5ca8cd491e940263c9f2515a43b5085d4451dbdf8c09acb3d1fe7001957ebeda65a3cd26f1d19fb3db3b06baf5dc41cdcd3412728c8b57edaf5");
        genesis.creatorSignature = CSchnorrSigS("ced5d4d4f5967b80ca774324a5d9ab0569ec1f1608dfef6c1e439094dc3467d50b2116fa02f3e89753033e94628668298f61b43df046881c9312f3bccde46a3f");

        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
        genesis.hashPayload    = genesis.GetPayloadHash();

        consensus.hashGenesisBlock = genesis.GetHash();
#if SHOW_GENESIS_HASHES
        PRINT_HASHES;
// #else
        //assert(consensus.hashGenesisBlock == uint256S("beed44fa5e96150d95d56ebd5d2625781825a9407a5215dd7eda723373a0a1d7"));
        //assert(genesis.hashMerkleRoot == uint256S("7c27ade2c28e67ed3077f8f77b8ea6d36d4f5eba04c099be3c9faa9a4a04c046"));
        //assert(genesis.hashPayload == uint256S("2b7ab86ef7189614d4bccb2576bffe834b7c0e6d3fd63539ea9fbbca45d26c0e"));
#endif
        vSeeds.push_back(CDNSSeedData("1.fair-coin.org", "faircoin2-seed1.fair-coin.org")); // Thomas König
        vSeeds.push_back(CDNSSeedData("2.fair-coin.org", "faircoin2-seed2.fair-coin.org")); // Thomas König

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,95);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,36);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,223);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fCreateBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

#if 0
        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 0, uint256S("49443ff1f4876f972e130e19c0969794aefd7aeb57ec65cdda386eea22a36cb2")),
            1462293889, // * UNIX timestamp of last checkpoint block
            0,   // * total number of transactions between genesis and last checkpoint
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0.0     // * estimated number of transactions per day after checkpoint
        };
#endif
    }
};
static CMainParams mainParams;

/**
 * Testnet
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        pchMessageStart[0] = 0x0c;
        pchMessageStart[1] = 0x12;
        pchMessageStart[2] = 0x0a;
        pchMessageStart[3] = 0x08;
        vAlertPubKey = ParseHex("045894f38e9dd72b6f210c261d40003eb087030c42b102d3b238b396256d02f5a380ff3b7444d306d9e118fa1fc7b2b7594875f4eb64bbeaa31577391d85eb5a8a");
        nDefaultPort = 41404;
        nPruneAfterHeight = 1000;

        CDynamicChainParams dynParams;
        dynParams.nBlockSpacing                = 2 * 60; // 3 min.
        dynParams.nBlockSpacingGracePeriod     = 45;
        dynParams.nMaxAdminSigs                = 11;
        dynParams.nMinAdminSigs                = 1;
        dynParams.nTransactionFee              = 10 * CENT; // 0.1 FAIR per Kb
        dynParams.nDustThreshold               = 10 * CENT; // 0.1 FAIR
        dynParams.nMinSuccessiveSignatures     = 1;
        dynParams.nBlocksToConsiderForSigCheck = 1;
        dynParams.nPercentageOfSignaturesMean  = 70; // 70%
        dynParams.nMaxBlockSize                = 1500000; // 1.5Mb
        dynParams.nBlockPropagationWaitTime    = 50; // 50 sec.
        dynParams.nRetryNewSigSetInterval      = 15; // 15 sec.
        dynParams.nCoinbaseMaturity            = 10; // 10 blocks = 30 min.
        dynParams.strDescription               = "#00001 https://fair-coin.org/ The genesis dynamic chain parameters";

        genesis = CreateGenesisBlock(GENESIS_BLOCK_TIMESTAMP + 1, GENESIS_NODE_ID, dynParams);

        genesis.vCvns.resize(1);
        genesis.vCvns[0] = CCvnInfo(GENESIS_NODE_ID, 0, CSchnorrPubKeyDER("04e3df8856c599be68f0293d858e822149a3c0f2a213e7772174c7071aacbefb889b9d04923bfc9563470b1eeefafb9996fb78820def4a5dd2bc1a30be99735ff3"));

        genesis.vChainAdmins.resize(1);
        genesis.vChainAdmins[0] = CChainAdmin(GENESIS_ADMIN_ID, 0, CSchnorrPubKeyDER("04d395225ac54e33ce6f0fb870264b8380c38ad9081938696fbd9cd5a5941c8d4d7edc51c3df6b16457700018bd83d5157fa02c339ec34d847aed7cd01f248b729"));

        genesis.chainMultiSig = CSchnorrSigS("1a59b40f34f32d192c9bd21281cb759390a1e7c128e9fe7083f5bb1a812c3bd4eb1a2a0f0f8cc0c2a12e2bbc88c01bddb6afe105870b7dbe5c4dd61a6866a172");
        genesis.vAdminIds.push_back(GENESIS_ADMIN_ID);
        genesis.adminMultiSig = CSchnorrSigS("15079311d3c42034de04c092d12269ef44af6bd956317da830583d90b0ef333540be613074ee6a63b16d41f7d05748ec24efe0751f2706c97165b777eecce212");
        genesis.creatorSignature = CSchnorrSigS("5fa8e6e24888f90ed3d72454b0c543fc8034f5932abf1d85c7be58d99339b0873bf52410799ffcd5a4e1002c41ba62db269492e63f93c04aaa14c988dbf9a610");

        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
        genesis.hashPayload    = genesis.GetPayloadHash();

        consensus.hashGenesisBlock = genesis.GetHash();
#if SHOW_GENESIS_HASHES
        PRINT_HASHES;
#else
        assert(consensus.hashGenesisBlock == uint256S("f06589d3cc0e046efd3c1737c8224c3b00b88dc4fbb7e9affacbb4683b926569"));
        assert(genesis.hashMerkleRoot == uint256S("83d3fcf89ff72d3fefea861975379dcaf12eb653c7fc727528794d256c30c08b"));
        assert(genesis.hashPayload == uint256S("de4b42626742659232a2b949acf9db694a826e5dad208f744dade527271a8cb5"));
#endif
        vFixedSeeds.clear();
        vSeeds.clear();
        // vSeeds.push_back(CDNSSeedData("1.fair-coin.org", "faircoin2-testnet-seed1.fair-coin.org")); // Thomas König

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fCreateBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

#if 0
        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 0, uint256S("fac71114e0630bb4c8722144ea843fcc8b465ac77820e86251d37141bd3da26e")),
            1461766275,
            1488,
            300
        };
#endif
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

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 42404;
        nPruneAfterHeight = 1000;

        CDynamicChainParams dynParams;
        dynParams.nBlockSpacing                = 1 * 60; // 3 min.
        dynParams.nBlockSpacingGracePeriod     = 30;
        dynParams.nMaxAdminSigs                = 11;
        dynParams.nMinAdminSigs                = 1;
        dynParams.nTransactionFee              = 10 * CENT; // 0.1 FAIR per Kb
        dynParams.nDustThreshold               = 10 * CENT; // 0.1 FAIR
        dynParams.nMinSuccessiveSignatures     = 1;
        dynParams.nBlocksToConsiderForSigCheck = 1;
        dynParams.nPercentageOfSignaturesMean  = 70; // 70%
        dynParams.nMaxBlockSize                = 1500000; // 1.5Mb
        dynParams.nBlockPropagationWaitTime    = 20; // 20 sec.
        dynParams.nRetryNewSigSetInterval      = 7; // 7 sec.
        dynParams.nCoinbaseMaturity            = 10; // 10 blocks = 30 min.
        dynParams.strDescription               = "#00001 https://fair-coin.org/ The genesis dynamic chain parameters";

        genesis = CreateGenesisBlock(GENESIS_BLOCK_TIMESTAMP + 2, GENESIS_NODE_ID, dynParams);

        genesis.vCvns.resize(1);
        genesis.vCvns[0] = CCvnInfo(GENESIS_NODE_ID, 0, CSchnorrPubKeyDER("04e3df8856c599be68f0293d858e822149a3c0f2a213e7772174c7071aacbefb889b9d04923bfc9563470b1eeefafb9996fb78820def4a5dd2bc1a30be99735ff3"));

        genesis.vChainAdmins.resize(1);
        genesis.vChainAdmins[0] = CChainAdmin(GENESIS_ADMIN_ID, 0, CSchnorrPubKeyDER("04d395225ac54e33ce6f0fb870264b8380c38ad9081938696fbd9cd5a5941c8d4d7edc51c3df6b16457700018bd83d5157fa02c339ec34d847aed7cd01f248b729"));

        genesis.chainMultiSig = CSchnorrSigS("1a59b40f34f32d192c9bd21281cb759390a1e7c128e9fe7083f5bb1a812c3bd4eb1a2a0f0f8cc0c2a12e2bbc88c01bddb6afe105870b7dbe5c4dd61a6866a172");
        genesis.vAdminIds.push_back(GENESIS_ADMIN_ID);
        genesis.adminMultiSig = CSchnorrSigS("6c1bd95cbfcd49651a79b403f3237926d7492142357c456f4aef7844359ef23820f2da5a31f906b267a1f295534ef3c20f96fb51c0ef3d436c13747fb2e1594b");
        genesis.creatorSignature = CSchnorrSigS("49c95dfbb749d1ee9610a36eca94d1ceb3da221fc72dcd6e0e0ba7a52446da6c319be3b417ab528dd0dca830f5a6891000bb4542bc813a1a6610b6b4aefb81f4");

        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
        genesis.hashPayload    = genesis.GetPayloadHash();

        consensus.hashGenesisBlock = genesis.GetHash();
#if SHOW_GENESIS_HASHES
        PRINT_HASHES;
//#else
        //assert(consensus.hashGenesisBlock == uint256S("335a7133066fe45cc6b1b7d48a5b589153bec2df38c069caf6c05a96f2ec0b76"));
        //assert(genesis.hashMerkleRoot == uint256S("7c27ade2c28e67ed3077f8f77b8ea6d36d4f5eba04c099be3c9faa9a4a04c046"));
        //assert(genesis.hashPayload == uint256S("10f08b71d33acab5031e62f2d6987398567e04988ed5810a893f12a72f3f5193"));
#endif
        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fCreateBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

#if 0
        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("fac71114e0630bb4c8722144ea843fcc8b465ac77820e86251d37141bd3da26e")),
            1461766275,
            0,
            0
        };
#endif
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
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

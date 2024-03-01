// SPDX-Identifier-License: MIT
pragma solidity ^0.8.17;

import {EIP712} from '../../helpers/EIP712.sol';
import {Errors} from '../../libraries/Errors.sol';
import {IClaveAccount} from '../../interfaces/IClave.sol';
import {BaseRecovery} from './base/BaseRecovery.sol';

import {MockGroth16Verifier} from "../../test/MockGroth16Verifier.sol";
import {MockDKIMRegsitry} from "../../test/MockDKIMRegsitry.sol";
import {IDKIMRegsitry} from "../../interfaces/IDKIMRegsitry.sol";

/**
 * @title Email Recovery Module
 * @notice Recovers the account using email guardians
 * @author wax
 */
contract EmailRecoveryModule is BaseRecovery {
    /** Default DKIM public key hashes registry */
    IDKIMRegsitry public immutable defaultDkimRegistry;

    MockGroth16Verifier public immutable verifier;

    // Accounts recovery config states
    struct RecoveryConfig {
        uint128 timelock; // Recovery timelock duration
        uint128 threshold; // Recovery threshold
        bytes32[] guardianHashes; // Guardian hashes
    }

    // Prepared guardian data for the recoveries
    struct GuardianData {
        bytes32 guardianHash; // Guardian hash
        bytes32 dkimPublicKeyHash; // DKIM public key hash
        string emailDomain; // email domain
        uint256[2] a; // part of proof
        uint256[2][2] b; // part of proof
        uint256[2] c; // part of proof
    }

    uint128 public immutable MIN_TIMELOCK;
    uint128 public immutable MIN_THRESHOLD;

    mapping(address => RecoveryConfig) recoveryConfigs;

    /** Mapping of account address to dkim registry address */
    mapping(address => address) public dkimRegistryOfAccount;

    event UpdateConfig(address indexed account, RecoveryConfig config);

    error INVALID_DKIM_KEY_HASH(
        address recoveringAddress,
        string emailDomain,
        bytes32 dkimPublicKeyHash
    );

    /**
     * @notice Constructor function of the module
     * @param name string memory    - eip712 name
     * @param version string memory - eip712 version
     * @param minTimelock uint 128  - minimum timelock for recovery configs
     * @param minThreshold uint128  - minimum threshold for recovery configs
     */
    constructor(
        string memory name,
        string memory version,
        uint128 minTimelock,
        uint128 minThreshold,
        address _verifier,
        address _defaultDkimRegistry
    ) EIP712(name, version) {
        MIN_TIMELOCK = minTimelock;
        MIN_THRESHOLD = minThreshold;
        verifier = MockGroth16Verifier(_verifier);
        defaultDkimRegistry = IDKIMRegsitry(_defaultDkimRegistry);
    }

    /**
     * @notice Initialize the module for the calling account with the given config
     * @dev Module must not be already inited for the account
     * @param initData bytes calldata - abi encoded RecoveryConfig
     */
    function init(bytes calldata initData) external override {
        if (isInited(msg.sender)) {
            revert Errors.ALREADY_INITED();
        }

        if (!IClaveAccount(msg.sender).isModule(address(this))) {
            revert Errors.MODULE_NOT_ADDED_CORRECTLY();
        }

        (
            uint128 _timelock,
            uint128 _threshold,
            bytes32[] memory _guardianHashes
        ) = abi.decode(initData, (uint128, uint128, bytes32[]));
        RecoveryConfig memory config = RecoveryConfig(
            _timelock,
            _threshold,
            _guardianHashes
        );

        emit Inited(msg.sender);

        _updateConfig(config);
    }

    /**
     * @notice Disable the module for the calling account
     * @dev Stops any recovery in progress
     */
    function disable() external override {
        if (!isInited(msg.sender)) {
            revert Errors.RECOVERY_NOT_INITED();
        }

        if (IClaveAccount(msg.sender).isModule(address(this))) {
            revert Errors.MODULE_NOT_REMOVED_CORRECTLY();
        }

        delete recoveryConfigs[msg.sender];

        emit Disabled(msg.sender);

        _stopRecovery();
    }

    /**
     * @notice Set a new config for the calling account
     * @dev Module must be inited for the account
     * @dev Account must not have a recovery in progress
     * @param config RecoveryConfig memory - new recovery config
     */
    function updateConfig(RecoveryConfig memory config) external {
        if (!isInited(msg.sender)) {
            revert Errors.RECOVERY_NOT_INITED();
        }

        if (isRecovering(msg.sender)) {
            revert Errors.RECOVERY_IN_PROGRESS();
        }

        _updateConfig(config);
    }

    /**
     * @notice Starts a recovery process for the given account
     * @dev Module must be inited for the account
     * @dev Account must not have a recovery in progress
     * @dev Checks the validity of the guardians and their email proofs
     * @param recoveryData RecoveryData calldata   - Data for the recovery process
     * @param guardianData GuardianData[] calldata - Guardian hashes and their email proofs
     */
    function startRecovery(
        RecoveryData calldata recoveryData,
        GuardianData[] calldata guardianData
    ) external {
        // Get the recovery address
        address recoveringAddress = recoveryData.recoveringAddress;

        // Check if an account is already on recovery progress
        if (isRecovering(recoveringAddress)) {
            revert Errors.RECOVERY_IN_PROGRESS();
        }

        // Check if the account recovery is inited
        if (!isInited(recoveringAddress)) {
            revert Errors.RECOVERY_NOT_INITED();
        }

        RecoveryConfig memory config = recoveryConfigs[recoveringAddress];

        // Check if the nonce is correct
        if (recoveryData.nonce != recoveryNonces[recoveringAddress]) {
            revert Errors.INVALID_RECOVERY_NONCE();
        }

        // TODO: Decide what to do with this
        // bytes32 eip712Hash = _hashTypedDataV4(_recoveryDataHash(recoveryData));

        // Check guardian data

        uint256 validGuardians = 0;
        bytes32 lastGuardianHash;
        for (uint256 i = 0; i < guardianData.length; ) {
            GuardianData memory data = guardianData[i];
            bytes32 guardianHash = data.guardianHash;

            if (guardianHash <= lastGuardianHash) {
                revert Errors.GUARDIANS_MUST_BE_SORTED();
            }

            lastGuardianHash = guardianHash;

            bool isGuardian;
            for (uint256 j = 0; j < config.guardianHashes.length; ) {
                if (guardianHash == config.guardianHashes[j]) {
                    isGuardian = true;
                    break;
                }

                unchecked {
                    j++;
                }
            }

            if (!isGuardian) {
                revert Errors.INVALID_GUARDIAN();
            }

            if (
                !this.isDKIMPublicKeyHashValid(
                    recoveringAddress,
                    data.emailDomain,
                    data.dkimPublicKeyHash
                )
            ) {
                revert INVALID_DKIM_KEY_HASH(
                    recoveringAddress,
                    data.emailDomain,
                    data.dkimPublicKeyHash
                );
            }

            bytes32[2] memory publicKey = abi.decode(
                recoveryData.newOwner,
                (bytes32[2])
            );

            uint256[5] memory publicSignals = [
                uint256(uint160(recoveringAddress)),
                uint256(guardianHash),
                uint256(publicKey[0]),
                uint256(publicKey[1]),
                uint256(data.dkimPublicKeyHash)
            ];

            if (verifier.verifyProof(data.a, data.b, data.c, publicSignals)) {
                validGuardians++;
            }

            unchecked {
                i++;
            }
        }

        // Check recovering guardian amount
        if (validGuardians < config.threshold) {
            revert Errors.INSUFFICIENT_GUARDIANS();
        }

        // Create recovery state
        recoveryStates[recoveringAddress] = RecoveryState(
            block.timestamp + config.timelock,
            recoveryData.newOwner
        );

        recoveryNonces[recoveringAddress]++;

        emit RecoveryStarted(
            recoveringAddress,
            recoveryData.newOwner,
            block.timestamp + config.timelock
        );
    }

    /// @notice Return the DKIM public key hash for a given email domain and account address
    /// @param account The address of the account that controls the module
    /// @param emailDomain Email domain for which the DKIM public key hash is to be returned
    function isDKIMPublicKeyHashValid(
        address account,
        string memory emailDomain,
        bytes32 publicKeyHash
    ) public view returns (bool) {
        address dkimRegistry = dkimRegistryOfAccount[account];

        if (dkimRegistry == address(0)) {
            dkimRegistry = address(defaultDkimRegistry);
        }

        return
            IDKIMRegsitry(dkimRegistry).isDKIMPublicKeyHashValid(
                emailDomain,
                publicKeyHash
            );
    }

    /// @inheritdoc BaseRecovery
    function isInited(address account) public view override returns (bool) {
        return recoveryConfigs[account].timelock != 0;
    }

    function _updateConfig(RecoveryConfig memory config) internal {
        if (!_isValidConfig(config)) {
            revert Errors.INVALID_RECOVERY_CONFIG();
        }

        recoveryConfigs[msg.sender] = config;

        emit UpdateConfig(msg.sender, config);
    }

    function _isValidConfig(RecoveryConfig memory config) private view returns (bool) {
        return
            config.timelock > MIN_TIMELOCK &&
            config.threshold <= config.guardianHashes.length &&
            config.threshold > MIN_THRESHOLD;
    }
}
// SPDX-License-Identifier: LGPL-3.0
pragma solidity 0.8.17;

/// @notice TPM-bound consensus identity registry for TGPoW.
/// @dev TPM evidence is evaluated off chain by an epoch-scoped validator set.
///      The contract only accepts one registration statement after signatures
///      from `threshold` distinct validators. The registration mapping and its
///      struct layout must remain unchanged because WorldLand consensus reads
///      the storage directly from parent state.
contract TPMDIDRegistry {
    struct Registration {
        address controller;
        bytes32 workKeyHash;
        bytes32 vrfKeyHash;
        bytes32 profileHash;
        bytes32 deviceNullifier;
        bool active;
    }

    struct RegistrationRequest {
        address controller;
        uint64 validatorEpoch;
        uint64 deadline;
        bool finalized;
        bytes32 statementHash;
        uint256 collateral;
    }

    struct EnrollmentData {
        bytes32 did;
        bytes32 workKeyHash;
        bytes32 vrfKeyHash;
        bytes32 profileHash;
        bytes32 deviceNullifier;
        bytes32 evidenceHash;
    }

    struct ProducerRequest {
        uint64 firstSlot;
        uint64 lastSlot;
        uint64 responseDeadline;
        uint16 threshold;
        uint16 approvals;
    }

    struct ProducerSlot {
        address producer;
        bytes32 credentialHash;
        bytes32 commitment;
        bytes32 evidenceHash;
        bool responded;
        bool approved;
    }

    // Consensus-critical legacy layout. Do not reorder slots 0 through 4 or
    // fields in Registration without changing consensus/VCT/tpm_registry.go.
    mapping(bytes32 => Registration) private registrations; // slot 0
    mapping(bytes32 => bool) public usedNullifiers; // slot 1
    uint256 public fixedCollateral; // slot 2
    address public governor; // slot 3 (the prototype used this as registrar)
    mapping(bytes32 => uint256) public collateralByDID; // slot 4

    // Threshold enrollment state starts after the consensus-critical layout.
    uint64 public registrationTTL;
    uint64 public activationDelay;
    uint64 public currentValidatorEpoch;
    mapping(uint64 => uint16) public thresholdByEpoch;
    mapping(uint64 => uint16) public validatorCountByEpoch;
    mapping(uint64 => bytes32) public policyDigestByEpoch;
    mapping(uint64 => mapping(address => bool)) public validatorByEpoch;
    mapping(address => uint256) public requestNonce;
    mapping(bytes32 => RegistrationRequest) public requests;
    mapping(bytes32 => bool) public registeredDIDs;
    mapping(bytes32 => bool) public revokedDIDs;
    mapping(bytes32 => uint256) public activationBlockByDID;

    // Dynamic block-producer committee configuration and state. These are
    // appended so the legacy consensus-visible layout above remains stable.
    uint16 public producerSlotCount;
    uint16 public producerThreshold;
    uint32 public producerSlotDelay;
    uint32 public producerResponseWindow;
    bytes32 public producerPolicyDigest;
    mapping(bytes32 => ProducerRequest) public producerRequests;
    mapping(bytes32 => mapping(uint64 => ProducerSlot)) public producerSlots;
    mapping(bytes32 => bytes32) public producerRequestIdentity;
    mapping(bytes32 => bytes32) public producerRequestPolicyDigest;

    bytes32 public constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 public constant ENROLLMENT_TYPEHASH = keccak256(
        "Enrollment(bytes32 requestId,bytes32 did,address controller,bytes32 workKeyHash,bytes32 vrfKeyHash,bytes32 profileHash,bytes32 deviceNullifier,bytes32 policyDigest,bytes32 evidenceHash,uint64 validatorEpoch,uint64 deadline)"
    );
    bytes32 public constant NAME_HASH = keccak256("WorldLand TPM DID Registry");
    bytes32 public constant VERSION_HASH = keccak256("2");
    bytes32 public constant DID_DOMAIN = keccak256("WorldLand TPM DID v1");
    bytes32 public constant PRODUCER_ENROLLMENT_TYPEHASH = keccak256(
        "ProducerEnrollment(bytes32 requestId,bytes32 identity,address controller,bytes32 workKeyHash,bytes32 vrfKeyHash,bytes32 profileHash,bytes32 deviceNullifier,bytes32 policyDigest,bytes32 evidenceHash,uint64 firstSlot,uint64 lastSlot,uint64 responseDeadline)"
    );
    bytes32 public constant PRODUCER_CHALLENGE_DOMAIN = keccak256("WorldLand TGPoW producer challenge v1");
    bytes32 public constant PRODUCER_APPROVAL_DOMAIN = keccak256("WorldLand TGPoW producer approval v1");
    bytes32 public constant PRODUCER_CERTIFY_DOMAIN = keccak256("WorldLand TGPoW certify challenge v1");

    event RegistrationRequested(
        bytes32 indexed requestId,
        bytes32 indexed did,
        address indexed controller,
        uint64 validatorEpoch,
        uint64 deadline,
        bytes32 statementHash,
        bytes32 evidenceHash
    );
    event RegistrationFinalized(
        bytes32 indexed requestId,
        bytes32 indexed did,
        address indexed controller,
        uint256 activationBlock
    );
    event Registered(bytes32 indexed did, address indexed controller, bytes32 indexed deviceNullifier);
    event RegistrationExpired(bytes32 indexed requestId, address indexed controller, uint256 refundedCollateral);
    event Revoked(bytes32 indexed did);
    event GovernorChanged(address indexed oldGovernor, address indexed newGovernor);
    event ValidatorEpochConfigured(uint64 indexed epoch, uint16 threshold, bytes32 indexed policyDigest);
    event ProducerCommitteeConfigured(
        uint16 slotCount,
        uint16 threshold,
        uint32 slotDelay,
        uint32 responseWindow,
        bytes32 indexed policyDigest
    );
    event ProducerRegistrationRequested(
        bytes32 indexed requestId,
        bytes32 indexed identity,
        address indexed controller,
        uint64 firstSlot,
        uint64 lastSlot,
        uint64 responseDeadline,
        bytes32 statementHash,
        bytes evidenceBundle
    );
    event ProducerChallengePublished(
        bytes32 indexed requestId,
        uint64 indexed slot,
        address indexed producer,
        bytes credentialBlob,
        bytes encryptedSecret,
        bytes32 commitment
    );
    event ProducerResponseSubmitted(
        bytes32 indexed requestId,
        uint64 indexed slot,
        bytes32 indexed evidenceHash,
        bytes evidenceBundle
    );
    event ProducerSlotApproved(bytes32 indexed requestId, uint64 indexed slot, address indexed producer);

    modifier onlyGovernor() {
        require(msg.sender == governor, "TPMRegistry: governor only");
        _;
    }

    constructor(
        uint256 collateral,
        address initialGovernor,
        uint64 requestTTL,
        uint64 didActivationDelay,
        address[] memory initialValidators,
        uint16 initialThreshold,
        bytes32 initialPolicyDigest
    ) {
        require(initialGovernor != address(0), "TPMRegistry: zero governor");
        require(requestTTL != 0, "TPMRegistry: zero TTL");
        fixedCollateral = collateral;
        governor = initialGovernor;
        registrationTTL = requestTTL;
        activationDelay = didActivationDelay;
        if (initialValidators.length != 0) {
            _configureValidatorEpoch(initialValidators, initialThreshold, initialPolicyDigest);
        } else {
            require(initialThreshold == 0 && initialPolicyDigest == bytes32(0), "TPMRegistry: partial validator config");
        }
    }

    /// @notice Derive the chain-specific DID from a permanent device nullifier.
    function deriveDID(bytes32 deviceNullifier) public view returns (bytes32) {
        require(deviceNullifier != bytes32(0), "TPMRegistry: zero nullifier");
        return keccak256(abi.encode(DID_DOMAIN, block.chainid, address(this), deviceNullifier));
    }

    /// @notice Open an enrollment request and escrow the fixed collateral.
    /// @dev `evidenceHash` commits to EKCert, canonical EK/AK public areas and
    ///      work-key certification evidence held by the off-chain validators.
    function beginRegistration(EnrollmentData calldata enrollment) external payable returns (bytes32 requestId) {
        require(enrollment.did == deriveDID(enrollment.deviceNullifier), "TPMRegistry: non-canonical DID");
        require(
            enrollment.workKeyHash != bytes32(0) && enrollment.vrfKeyHash != bytes32(0),
            "TPMRegistry: zero key hash"
        );
        require(enrollment.profileHash != bytes32(0), "TPMRegistry: zero profile hash");
        require(enrollment.evidenceHash != bytes32(0), "TPMRegistry: zero evidence hash");
        require(
            !registeredDIDs[enrollment.did] && registrations[enrollment.did].controller == address(0),
            "TPMRegistry: DID already registered"
        );
        require(!usedNullifiers[enrollment.deviceNullifier], "TPMRegistry: device already used");
        require(msg.value == fixedCollateral, "TPMRegistry: wrong collateral");

        uint64 epoch = currentValidatorEpoch;
        require(thresholdByEpoch[epoch] != 0, "TPMRegistry: validator epoch inactive");
        uint64 deadline = uint64(block.number) + registrationTTL;
        uint256 nonce = requestNonce[msg.sender]++;
        requestId = keccak256(abi.encode(address(this), block.chainid, msg.sender, nonce));
        bytes32 statementHash = enrollmentStatementHash(
            requestId,
            msg.sender,
            enrollment,
            epoch,
            deadline
        );
        requests[requestId] = RegistrationRequest({
            controller: msg.sender,
            validatorEpoch: epoch,
            deadline: deadline,
            finalized: false,
            statementHash: statementHash,
            collateral: msg.value
        });
        emit RegistrationRequested(
            requestId,
            enrollment.did,
            msg.sender,
            epoch,
            deadline,
            statementHash,
            enrollment.evidenceHash
        );
    }

    /// @notice Open enrollment using the next n block producers as a dynamic
    ///         hashpower-weighted committee. This is the TGPoW registration path.
    function beginProducerRegistration(
        EnrollmentData calldata enrollment,
        bytes calldata evidenceBundle
    ) external payable returns (bytes32 requestId) {
        _validateNewEnrollment(enrollment);
        require(evidenceBundle.length != 0 && keccak256(evidenceBundle) == enrollment.evidenceHash, "TPMRegistry: evidence bundle mismatch");
        require(producerSlotCount != 0 && producerThreshold != 0, "TPMRegistry: producer committee inactive");
        require(msg.value == fixedCollateral, "TPMRegistry: wrong collateral");

        uint64 firstSlot = uint64(block.number) + uint64(producerSlotDelay) + 1;
        uint64 lastSlot = firstSlot + uint64(producerSlotCount) - 1;
        uint64 responseDeadline = lastSlot + uint64(producerResponseWindow);
        uint256 nonce = requestNonce[msg.sender]++;
        requestId = keccak256(abi.encode(address(this), block.chainid, msg.sender, nonce));
        bytes32 statementHash = producerEnrollmentStatementHash(
            requestId, msg.sender, enrollment, firstSlot, lastSlot, responseDeadline
        );
        requests[requestId] = RegistrationRequest({
            controller: msg.sender,
            validatorEpoch: 0,
            deadline: responseDeadline,
            finalized: false,
            statementHash: statementHash,
            collateral: msg.value
        });
        producerRequests[requestId] = ProducerRequest({
            firstSlot: firstSlot,
            lastSlot: lastSlot,
            responseDeadline: responseDeadline,
            threshold: producerThreshold,
            approvals: 0
        });
        producerRequestIdentity[requestId] = enrollment.did;
        producerRequestPolicyDigest[requestId] = producerPolicyDigest;
        emit ProducerRegistrationRequested(
            requestId, enrollment.did, msg.sender, firstSlot, lastSlot, responseDeadline, statementHash, evidenceBundle
        );
    }

    /// @notice Record MakeCredential material in its designated producer slot.
    /// @dev A relayer may submit it, but the signature must be from this block's
    ///      coinbase and is valid only for this exact slot and payload.
    function publishProducerChallenge(
        bytes32 requestId,
        bytes calldata credentialBlob,
        bytes calldata encryptedSecret,
        bytes32 commitment,
        bytes calldata producerSignature
    ) external {
        ProducerRequest storage producerRequest = producerRequests[requestId];
        uint64 slot = uint64(block.number);
        require(slot >= producerRequest.firstSlot && slot <= producerRequest.lastSlot, "TPMRegistry: outside slot window");
        require(credentialBlob.length != 0 && encryptedSecret.length != 0, "TPMRegistry: empty credential");
        require(commitment != bytes32(0), "TPMRegistry: zero commitment");
        ProducerSlot storage item = producerSlots[requestId][slot];
        require(item.producer == address(0), "TPMRegistry: slot already filled");
        bytes32 credentialHash = keccak256(abi.encode(credentialBlob, encryptedSecret));
        bytes32 digest = producerChallengeDigest(requestId, slot, block.coinbase, credentialHash, commitment);
        require(_recover(digest, producerSignature) == block.coinbase, "TPMRegistry: not block producer");
        item.producer = block.coinbase;
        item.credentialHash = credentialHash;
        item.commitment = commitment;
        emit ProducerChallengePublished(
            requestId, slot, block.coinbase, credentialBlob, encryptedSecret, commitment
        );
    }

    /// @notice Reveal the ActivateCredential result and commit to Certify evidence.
    ///         The commitment preimage is checked entirely on chain.
    function submitProducerResponse(
        bytes32 requestId,
        uint64 slot,
        bytes32 secret,
        bytes calldata evidenceBundle
    ) external {
        RegistrationRequest storage request = requests[requestId];
        ProducerRequest storage producerRequest = producerRequests[requestId];
        require(request.controller == msg.sender, "TPMRegistry: controller only");
        require(!request.finalized && block.number <= producerRequest.responseDeadline, "TPMRegistry: request closed");
        ProducerSlot storage item = producerSlots[requestId][slot];
        require(item.producer != address(0) && !item.responded, "TPMRegistry: invalid slot response");
        require(evidenceBundle.length != 0, "TPMRegistry: empty evidence");
        require(
            producerChallengeCommitment(
                requestId, request.statementHash, slot, item.producer, item.credentialHash, secret
            ) == item.commitment,
            "TPMRegistry: commitment mismatch"
        );
        bytes32 evidenceHash = keccak256(evidenceBundle);
        item.evidenceHash = evidenceHash;
        item.responded = true;
        emit ProducerResponseSubmitted(requestId, slot, evidenceHash, evidenceBundle);
    }

    /// @notice Submit the slot producer's approval after off-chain Certify validation.
    function approveProducerSlot(
        bytes32 requestId,
        uint64 slot,
        bytes32 identity,
        bytes calldata producerSignature
    ) external {
        RegistrationRequest storage request = requests[requestId];
        ProducerRequest storage producerRequest = producerRequests[requestId];
        require(!request.finalized && block.number <= producerRequest.responseDeadline, "TPMRegistry: request closed");
        ProducerSlot storage item = producerSlots[requestId][slot];
        require(item.responded && !item.approved, "TPMRegistry: slot not approvable");
        require(identity == producerRequestIdentity[requestId], "TPMRegistry: wrong identity");
        bytes32 digest = producerApprovalDigest(
            requestId, slot, item.commitment, item.evidenceHash, identity, producerRequest.responseDeadline
        );
        require(_recover(digest, producerSignature) == item.producer, "TPMRegistry: invalid producer approval");
        item.approved = true;
        producerRequest.approvals++;
        emit ProducerSlotApproved(requestId, slot, item.producer);
    }

    function finalizeProducerRegistration(bytes32 requestId, EnrollmentData calldata enrollment) external {
        RegistrationRequest storage request = requests[requestId];
        ProducerRequest storage producerRequest = producerRequests[requestId];
        require(request.controller == msg.sender, "TPMRegistry: controller only");
        require(!request.finalized && block.number <= producerRequest.responseDeadline, "TPMRegistry: request closed");
        require(producerRequest.threshold != 0 && producerRequest.approvals >= producerRequest.threshold, "TPMRegistry: insufficient producer approvals");
        _validateNewEnrollment(enrollment);
        require(
            producerEnrollmentStatementHash(
                requestId,
                request.controller,
                enrollment,
                producerRequest.firstSlot,
                producerRequest.lastSlot,
                producerRequest.responseDeadline
            ) == request.statementHash,
            "TPMRegistry: statement changed"
        );
        _completeRegistration(requestId, request, enrollment);
    }

    /// @notice Finalize an enrollment after collecting a validator quorum.
    function finalizeRegistration(
        bytes32 requestId,
        EnrollmentData calldata enrollment,
        bytes[] calldata approvals
    ) external {
        RegistrationRequest storage request = requests[requestId];
        require(request.controller != address(0), "TPMRegistry: request missing");
        require(msg.sender == request.controller, "TPMRegistry: controller only");
        require(!request.finalized, "TPMRegistry: request finalized");
        require(block.number <= request.deadline, "TPMRegistry: request expired");
        require(
            !registeredDIDs[enrollment.did] && registrations[enrollment.did].controller == address(0),
            "TPMRegistry: DID already registered"
        );
        require(!usedNullifiers[enrollment.deviceNullifier], "TPMRegistry: device already used");
        require(
            enrollment.did == deriveDID(enrollment.deviceNullifier),
            "TPMRegistry: non-canonical DID"
        );

        uint64 epoch = request.validatorEpoch;
        bytes32 statementHash = enrollmentStatementHash(
            requestId,
            request.controller,
            enrollment,
            epoch,
            request.deadline
        );
        require(statementHash == request.statementHash, "TPMRegistry: statement changed");
        _verifyApprovals(epoch, statementHash, approvals);

        _completeRegistration(requestId, request, enrollment);
    }

    /// @notice Activate a finalized DID after the anti-key-grinding delay.
    function activate(bytes32 did) external {
        require(registeredDIDs[did], "TPMRegistry: DID missing");
        require(!revokedDIDs[did], "TPMRegistry: DID revoked");
        Registration storage item = registrations[did];
        require(!item.active, "TPMRegistry: DID active");
        require(block.number >= activationBlockByDID[did], "TPMRegistry: activation pending");
        item.active = true;
        emit Registered(did, item.controller, item.deviceNullifier);
    }

    /// @notice Refund an enrollment that did not reach a quorum before expiry.
    function cancelExpired(bytes32 requestId) external {
        RegistrationRequest storage request = requests[requestId];
        require(request.controller == msg.sender, "TPMRegistry: controller only");
        require(!request.finalized, "TPMRegistry: request finalized");
        require(block.number > request.deadline, "TPMRegistry: request live");
        uint256 amount = request.collateral;
        require(amount != 0, "TPMRegistry: no collateral");
        request.collateral = 0;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "TPMRegistry: refund failed");
        emit RegistrationExpired(requestId, msg.sender, amount);
    }

    function revoke(bytes32 did) external onlyGovernor {
        require(registrations[did].controller != address(0), "TPMRegistry: DID missing");
        require(!revokedDIDs[did], "TPMRegistry: DID revoked");
        registeredDIDs[did] = true;
        registrations[did].active = false;
        revokedDIDs[did] = true;
        emit Revoked(did);
    }

    function withdrawRevokedCollateral(bytes32 did) external {
        Registration storage item = registrations[did];
        require(revokedDIDs[did] && item.controller == msg.sender, "TPMRegistry: not revoked controller");
        uint256 amount = collateralByDID[did];
        require(amount != 0, "TPMRegistry: no collateral");
        collateralByDID[did] = 0;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "TPMRegistry: transfer failed");
    }

    function configureValidatorEpoch(
        address[] calldata validators,
        uint16 threshold,
        bytes32 policyDigest
    ) external onlyGovernor returns (uint64 epoch) {
        epoch = _configureValidatorEpoch(validators, threshold, policyDigest);
    }

    function configureProducerCommittee(
        uint16 slotCount,
        uint16 threshold,
        uint32 slotDelay,
        uint32 responseWindow,
        bytes32 policyDigest
    ) external onlyGovernor {
        require(slotCount != 0 && threshold != 0 && threshold <= slotCount, "TPMRegistry: invalid producer threshold");
        require(responseWindow != 0 && policyDigest != bytes32(0), "TPMRegistry: invalid producer policy");
        producerSlotCount = slotCount;
        producerThreshold = threshold;
        producerSlotDelay = slotDelay;
        producerResponseWindow = responseWindow;
        producerPolicyDigest = policyDigest;
        emit ProducerCommitteeConfigured(slotCount, threshold, slotDelay, responseWindow, policyDigest);
    }

    function setGovernor(address nextGovernor) external onlyGovernor {
        require(nextGovernor != address(0), "TPMRegistry: zero governor");
        emit GovernorChanged(governor, nextGovernor);
        governor = nextGovernor;
    }

    function registration(bytes32 did) external view returns (Registration memory) {
        return registrations[did];
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    function enrollmentStatementHash(
        bytes32 requestId,
        address controller,
        EnrollmentData calldata enrollment,
        uint64 validatorEpoch,
        uint64 deadline
    ) public view returns (bytes32) {
        return keccak256(abi.encode(
            ENROLLMENT_TYPEHASH,
            requestId,
            enrollment.did,
            controller,
            enrollment.workKeyHash,
            enrollment.vrfKeyHash,
            enrollment.profileHash,
            enrollment.deviceNullifier,
            policyDigestByEpoch[validatorEpoch],
            enrollment.evidenceHash,
            validatorEpoch,
            deadline
        ));
    }

    function approvalDigest(bytes32 statementHash) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), statementHash));
    }

    function producerEnrollmentStatementHash(
        bytes32 requestId,
        address controller,
        EnrollmentData calldata enrollment,
        uint64 firstSlot,
        uint64 lastSlot,
        uint64 responseDeadline
    ) public view returns (bytes32) {
        bytes32 requestPolicy = producerRequestPolicyDigest[requestId];
        if (requestPolicy == bytes32(0)) requestPolicy = producerPolicyDigest;
        return keccak256(abi.encode(
            PRODUCER_ENROLLMENT_TYPEHASH,
            requestId,
            enrollment.did,
            controller,
            enrollment.workKeyHash,
            enrollment.vrfKeyHash,
            enrollment.profileHash,
            enrollment.deviceNullifier,
            requestPolicy,
            enrollment.evidenceHash,
            firstSlot,
            lastSlot,
            responseDeadline
        ));
    }

    function producerChallengeCommitment(
        bytes32 requestId,
        bytes32 statementHash,
        uint64 slot,
        address producer,
        bytes32 credentialHash,
        bytes32 secret
    ) public view returns (bytes32) {
        return keccak256(abi.encode(
            PRODUCER_CHALLENGE_DOMAIN,
            block.chainid,
            address(this),
            requestId,
            statementHash,
            slot,
            producer,
            credentialHash,
            secret
        ));
    }

    function producerChallengeDigest(
        bytes32 requestId,
        uint64 slot,
        address producer,
        bytes32 credentialHash,
        bytes32 commitment
    ) public view returns (bytes32) {
        return keccak256(abi.encode(
            PRODUCER_CHALLENGE_DOMAIN,
            block.chainid,
            address(this),
            requestId,
            slot,
            producer,
            credentialHash,
            commitment
        ));
    }

    function producerApprovalDigest(
        bytes32 requestId,
        uint64 slot,
        bytes32 commitment,
        bytes32 evidenceHash,
        bytes32 identity,
        uint64 deadline
    ) public view returns (bytes32) {
        return keccak256(abi.encode(
            PRODUCER_APPROVAL_DOMAIN,
            block.chainid,
            address(this),
            requestId,
            slot,
            commitment,
            evidenceHash,
            identity,
            deadline
        ));
    }

    function producerCertifyChallenge(
        bytes32 requestId,
        uint64 slot,
        bytes32 commitment
    ) public view returns (bytes32) {
        return keccak256(abi.encode(
            PRODUCER_CERTIFY_DOMAIN,
            block.chainid,
            address(this),
            requestId,
            slot,
            commitment
        ));
    }

    function _validateNewEnrollment(EnrollmentData calldata enrollment) internal view {
        require(enrollment.did == deriveDID(enrollment.deviceNullifier), "TPMRegistry: non-canonical identity");
        require(enrollment.workKeyHash != bytes32(0) && enrollment.vrfKeyHash != bytes32(0), "TPMRegistry: zero key hash");
        require(enrollment.profileHash != bytes32(0), "TPMRegistry: zero profile hash");
        require(enrollment.evidenceHash != bytes32(0), "TPMRegistry: zero evidence hash");
        require(!registeredDIDs[enrollment.did] && registrations[enrollment.did].controller == address(0), "TPMRegistry: identity already registered");
        require(!usedNullifiers[enrollment.deviceNullifier], "TPMRegistry: device already used");
    }

    function _completeRegistration(
        bytes32 requestId,
        RegistrationRequest storage request,
        EnrollmentData calldata enrollment
    ) internal {
        request.finalized = true;
        uint256 collateral = request.collateral;
        request.collateral = 0;
        registeredDIDs[enrollment.did] = true;
        usedNullifiers[enrollment.deviceNullifier] = true;
        collateralByDID[enrollment.did] = collateral;
        uint256 activationBlock = block.number + activationDelay;
        activationBlockByDID[enrollment.did] = activationBlock;
        bool activeNow = activationDelay == 0;
        registrations[enrollment.did] = Registration({
            controller: request.controller,
            workKeyHash: enrollment.workKeyHash,
            vrfKeyHash: enrollment.vrfKeyHash,
            profileHash: enrollment.profileHash,
            deviceNullifier: enrollment.deviceNullifier,
            active: activeNow
        });
        emit RegistrationFinalized(requestId, enrollment.did, request.controller, activationBlock);
        if (activeNow) emit Registered(enrollment.did, request.controller, enrollment.deviceNullifier);
    }

    function _configureValidatorEpoch(
        address[] memory validators,
        uint16 threshold,
        bytes32 policyDigest
    ) internal returns (uint64 epoch) {
        require(policyDigest != bytes32(0), "TPMRegistry: zero policy digest");
        require(validators.length != 0 && validators.length <= type(uint16).max, "TPMRegistry: invalid validators");
        require(threshold != 0 && threshold <= validators.length, "TPMRegistry: invalid threshold");
        epoch = currentValidatorEpoch + 1;
        currentValidatorEpoch = epoch;
        thresholdByEpoch[epoch] = threshold;
        validatorCountByEpoch[epoch] = uint16(validators.length);
        policyDigestByEpoch[epoch] = policyDigest;
        for (uint256 i = 0; i < validators.length; i++) {
            address validator = validators[i];
            require(validator != address(0), "TPMRegistry: zero validator");
            require(!validatorByEpoch[epoch][validator], "TPMRegistry: duplicate validator");
            validatorByEpoch[epoch][validator] = true;
        }
        emit ValidatorEpochConfigured(epoch, threshold, policyDigest);
    }

    function _verifyApprovals(
        uint64 epoch,
        bytes32 statementHash,
        bytes[] calldata approvals
    ) internal view {
        uint16 threshold = thresholdByEpoch[epoch];
        require(threshold != 0 && approvals.length >= threshold, "TPMRegistry: insufficient approvals");
        bytes32 digest = approvalDigest(statementHash);
        address[] memory recovered = new address[](approvals.length);
        uint256 valid;
        for (uint256 i = 0; i < approvals.length; i++) {
            address signer = _recover(digest, approvals[i]);
            require(validatorByEpoch[epoch][signer], "TPMRegistry: signer not validator");
            for (uint256 j = 0; j < valid; j++) {
                require(recovered[j] != signer, "TPMRegistry: duplicate signer");
            }
            recovered[valid++] = signer;
        }
        require(valid >= threshold, "TPMRegistry: insufficient approvals");
    }

    function _recover(bytes32 digest, bytes calldata signature) internal pure returns (address signer) {
        require(signature.length == 65, "TPMRegistry: invalid signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v < 27) {
            v += 27;
        }
        require(v == 27 || v == 28, "TPMRegistry: invalid signature v");
        require(
            uint256(s) <= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0,
            "TPMRegistry: non-canonical signature"
        );
        signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "TPMRegistry: invalid signature");
    }
}

// SPDX-License-Identifier: LGPL-3.0
pragma solidity ^0.8.20;

/// @notice Prototype TPM-DID registry for the TPM-gated VCT fork.
/// @dev The registrar is an explicit trust boundary in this first prototype.
///      It must verify the manufacturer chain, EK/AK evidence and work-key
///      certification off chain before authorizing register. The controller
///      submits that authorization and pays the fixed collateral. The client
///      reads the registration mapping directly from parent-state storage.
contract TPMDIDRegistry {
    struct Registration {
        address controller;
        bytes32 workKeyHash;
        bytes32 vrfKeyHash;
        bytes32 profileHash;
        bytes32 deviceNullifier;
        bool active;
    }

    // Keep this mapping at storage slot zero. WorldLand consensus derives its
    // slots using keccak256(abi.encode(did, uint256(0))).
    mapping(bytes32 => Registration) private registrations;
    mapping(bytes32 => bool) public usedNullifiers;

    // Non-immutable storage is intentional: a genesis predeploy must populate
    // these slots because constructors do not run when runtime code is placed
    // directly in the genesis allocation.
    uint256 public fixedCollateral;
    address public registrar;
    mapping(bytes32 => uint256) public collateralByDID;

    event Registered(bytes32 indexed did, address indexed controller, bytes32 indexed deviceNullifier);
    event Revoked(bytes32 indexed did);
    event RegistrarChanged(address indexed oldRegistrar, address indexed newRegistrar);

    modifier onlyRegistrar() {
        require(msg.sender == registrar, "TPMRegistry: registrar only");
        _;
    }

    constructor(uint256 collateral, address initialRegistrar) {
        require(initialRegistrar != address(0), "TPMRegistry: zero registrar");
        fixedCollateral = collateral;
        registrar = initialRegistrar;
    }

    function register(
        bytes32 did,
        address controller,
        bytes32 workKeyHash,
        bytes32 vrfKeyHash,
        bytes32 profileHash,
        bytes32 deviceNullifier,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external payable {
        require(did != bytes32(0), "TPMRegistry: zero DID");
        require(msg.sender == controller && controller != address(0), "TPMRegistry: controller only");
        require(workKeyHash != bytes32(0) && vrfKeyHash != bytes32(0), "TPMRegistry: zero key hash");
        require(deviceNullifier != bytes32(0), "TPMRegistry: zero nullifier");
        require(!registrations[did].active, "TPMRegistry: DID active");
        require(collateralByDID[did] == 0, "TPMRegistry: old collateral pending");
        require(!usedNullifiers[deviceNullifier], "TPMRegistry: device already used");
        require(msg.value == fixedCollateral, "TPMRegistry: wrong collateral");

        bytes32 authorization = keccak256(abi.encode(
            address(this), block.chainid, did, controller, workKeyHash,
            vrfKeyHash, profileHash, deviceNullifier
        ));
        bytes32 signedAuthorization = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", authorization));
        require(ecrecover(signedAuthorization, v, r, s) == registrar, "TPMRegistry: invalid attestation authorization");

        registrations[did] = Registration({
            controller: controller,
            workKeyHash: workKeyHash,
            vrfKeyHash: vrfKeyHash,
            profileHash: profileHash,
            deviceNullifier: deviceNullifier,
            active: true
        });
        usedNullifiers[deviceNullifier] = true;
        collateralByDID[did] = msg.value;
        emit Registered(did, controller, deviceNullifier);
    }

    function revoke(bytes32 did) external onlyRegistrar {
        require(registrations[did].active, "TPMRegistry: DID inactive");
        registrations[did].active = false;
        emit Revoked(did);
    }

    function withdrawRevokedCollateral(bytes32 did) external {
        Registration storage item = registrations[did];
        require(!item.active && item.controller == msg.sender, "TPMRegistry: not revoked controller");
        uint256 amount = collateralByDID[did];
        require(amount != 0, "TPMRegistry: no collateral");
        collateralByDID[did] = 0;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "TPMRegistry: transfer failed");
    }

    function setRegistrar(address nextRegistrar) external onlyRegistrar {
        require(nextRegistrar != address(0), "TPMRegistry: zero registrar");
        emit RegistrarChanged(registrar, nextRegistrar);
        registrar = nextRegistrar;
    }

    function registration(bytes32 did) external view returns (Registration memory) {
        return registrations[did];
    }
}

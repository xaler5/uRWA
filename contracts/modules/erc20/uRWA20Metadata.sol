// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {uRWA20} from "../../uRWA20.sol";

contract uRWA20Metadata is uRWA20 {

    bytes32 public constant DOCUMENT_ROLE = keccak256("DOCUMENT_ROLE");

    error DocumentNotFound(bytes32 _name);

    event DocumentRemoved(bytes32 indexed _name, string _uri, bytes32 _documentHash);
    event DocumentUpdated(bytes32 indexed _name, string _uri, bytes32 _documentHash);

    mapping(bytes32 name => string uri) private _documents;
    mapping(bytes32 name => bytes32 documentHash) private _documentHashes;
    mapping(bytes32 name => uint32 latestUpdate) private _documentUpdates;
    mapping(bytes32 name => uint256 indexPlusOne) private _documentIndex; // 0 means not listed
    bytes32[] private _documentNames;

    constructor(string memory name, string memory symbol, address initialAdmin)
        uRWA20(name, symbol, initialAdmin)
    {
        _grantRole(DOCUMENT_ROLE, initialAdmin);
    }

    function getDocument(bytes32 _name) external view returns (string memory, bytes32, uint256) {
        return (_documents[_name], _documentHashes[_name], _documentUpdates[_name]);
    }

    function setDocument(bytes32 _name, string memory _uri, bytes32 _documentHash) external onlyRole(DOCUMENT_ROLE) {
        _documents[_name] = _uri;
        _documentHashes[_name] = _documentHash;
        _documentUpdates[_name] = uint32(block.timestamp);
        if (_documentIndex[_name] == 0) { // updating an existing document must not list it twice
            _documentNames.push(_name);
            _documentIndex[_name] = _documentNames.length;
        }
        emit DocumentUpdated(_name, _uri, _documentHash);
    }

    function removeDocument(bytes32 _name) external onlyRole(DOCUMENT_ROLE) {
        uint256 indexPlusOne = _documentIndex[_name];
        require(indexPlusOne != 0, DocumentNotFound(_name));
        string memory uri = _documents[_name];
        bytes32 documentHash = _documentHashes[_name];
        delete _documents[_name];
        delete _documentHashes[_name];
        _documentUpdates[_name] = uint32(block.timestamp); // instead of deleting, we mark when it was deleted as latest update
        bytes32 lastName = _documentNames[_documentNames.length - 1];
        _documentNames[indexPlusOne - 1] = lastName;
        _documentIndex[lastName] = indexPlusOne;
        _documentNames.pop();
        delete _documentIndex[_name];
        emit DocumentRemoved(_name, uri, documentHash);
    }

    function getAllDocuments() external view returns (bytes32[] memory) {
        return _documentNames;
    }
}
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {uRWA20} from "../../uRWA20.sol";

contract uRWA20Metadata is uRWA20 {

    event DocumentRemoved(bytes32 indexed _name, string _uri, bytes32 _documentHash);
    event DocumentUpdated(bytes32 indexed _name, string _uri, bytes32 _documentHash);

    mapping(bytes32 name => string uri) private _documents;
    mapping(bytes32 name => bytes32 documentHash) private _documentHashes;
    mapping(bytes32 name => uint32 latestUpdate) private _documentUpdates;
    mapping(bytes32 name => uint256 index) private _documentIndex;
    bytes32[] private _documentNames;

    constructor(string memory name, string memory symbol, address initialAdmin)
        uRWA20(name, symbol, initialAdmin)
    {}

    function getDocument(bytes32 _name) external view returns (string memory, bytes32, uint256) {
        return (_documents[_name], _documentHashes[_name], _documentUpdates[_name]);
    }

    function setDocument(bytes32 _name, string memory _uri, bytes32 _documentHash) external {
        _documents[_name] = _uri;
        _documentHashes[_name] = _documentHash;
        _documentUpdates[_name] = uint32(block.timestamp);
        _documentNames.push(_name);
        _documentIndex[_name] = _documentNames.length - 1;
        emit DocumentUpdated(_name, _uri, _documentHash);
    }

    function removeDocument(bytes32 _name) external {
        string memory uri = _documents[_name];
        bytes32 documentHash = _documentHashes[_name];
        delete _documents[_name];
        delete _documentHashes[_name];
        _documentUpdates[_name] = uint32(block.timestamp); // instead of deleting, we mark when it was deleted as latest update
        _documentNames[_documentIndex[_name]] = _documentNames[_documentNames.length - 1];
        _documentNames.pop();
        emit DocumentRemoved(_name, uri, documentHash);
    }

    function getAllDocuments() external view returns (bytes32[] memory) {
        return _documentNames;
    }
}
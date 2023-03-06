const fs = require('fs');
const writeFileSync = require('fs');
const { MerkleTree } = require('merkletreejs')
const SHA256 = require('crypto-js/sha256')
const keccak256 = require('keccak256')
const { ethers } = require("hardhat");
var obj = require("../src/js/testAddress.js");
var testAddr = obj.array;


const generateMerkleTree = (data) => {
    const leaves = testAddr.map(x => keccak256(x));
    // console.log(leaves);
    const merkleTree = new MerkleTree(leaves, keccak256, { sortPairs: true });
    const merkleRoot = merkleTree.getHexRoot();

    return [merkleRoot, merkleTree];
};

const getProofOfLeaf = (leafdata, tree) => {
    const proof = tree.getProof(leafdata);
    console.log("proof of " + buf2hex(leafdata) + " is " + proof.map(x => buf2hex(x.data)));
}

const checkProof = (leafdata, tree, root) => {
    if (!tree.verify(proof, leafdata, root)) {
        console.err("Verification failed");
        return false;
    }
}


const checkTree = (testAddrData, tree, root) => {
    for (const addr of testAddrData) {
        const leaf = keccak256(addr);
        const proof = tree.getProof(leaf);

        // hex proof for solidity byte32[] input
        // const hexProof = tree.getHexProof(leaf);

        if (!tree.verify(proof, leaf, root)) {
            console.err("Verification failed");
            return false;
        }
    }

    return true;
};



function testMarkle() {
    const leaves = ['a', 'b', 'c'].map(x => keccak256(x))
    const tree = new MerkleTree(leaves, keccak256)
    const root = tree.getRoot().toString('hex')
    const leaf = keccak256('a')
    const proof = tree.getProof(leaf)
    // console.log(tree.verify(proof, leaf, root)) // true


    const badLeaves = ['a', 'x', 'c'].map(x => keccak256(x))
    const badTree = new MerkleTree(badLeaves, keccak256)
    const badLeaf = keccak256('x')
    const badProof = tree.getProof(badLeaf)
    // console.log(tree.verify(badProof, leaf, root)) // false
}


function buf2hex(buffer) { // buffer is an ArrayBuffer
    // return [...new Uint8Array(buffer)]
    //     .map(x => x.toString(16).padStart(0, '0'))
    //     .join('');
    return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}


async function main(outputPath) {
    const [merkleRoot, merkleTree] = generateMerkleTree(testAddr);
    console.log(merkleTree.toString())

    getProofOfLeaf(keccak256(testAddr[0]), merkleTree)
    if (checkTree(testAddr, merkleTree, merkleRoot)) {
        fs.writeFileSync(
            outputPath,
            JSON.stringify({
                root: merkleRoot,
                tree: merkleTree,
            })
        );

        console.log(`Successfully generate merkle tree to ${outputPath}.`);
    } else {
        console.err("Generate merkle tree failed.");
    }
    testMarkle()

    // testContractVerify
    const hexroot = merkleRoot
    const leaf = keccak256(testAddr[0]);
    const hexleaf = "0x" + buf2hex(leaf)
    const proof = merkleTree.getProof(leaf)
    //hexproof should match this format:
    /*
    ["0x8c17c9babe26f471e0fad9f6dc4e6e0c855a10016a2e613d8be32969e1bd04d3","0xf4fefbf2b950c467a0a03223ddb1d5ce61d6df4c0112a7433dfe8fa05cd9cbd6","0xdfcee74cc1bd88af159e13de7f311d0edb2794d50ba9d5a215a7cf6800cb8263","0xb74f307302654cd6ce71639b56bd94aae0098986875f7def2362a38aa4594f01","0x4332328b7566b7fa03cede58e26980ee05305c41310c599d71106b43e71cf001","0x1c15a3c4c7cdd8bfa25d81a41724b496912a47ff27bf13e9490dab23a467dd7c","0x7836e2e13557e9941cdf1a5e95fa3436dedacb6757268ecc3af5f1db16de3362"]
    */
    const hexproof = merkleTree.getProof(leaf).map(x => buf2hex(x.data))
    const byteproof = merkleTree.getProof(leaf).map(x => x.data)
    const positions = merkleTree.getProof(leaf).map(x => x.position === 'right' ? 1 : 0)

    console.log("hexroot = " + hexroot)
    console.log("hexleaf = ")
    console.log(hexleaf)
    console.log("hexproof = ")
    console.log(hexproof)
    console.log("positions = ")
    positions[5] = 0
    console.log(positions)

    const KYCManager = await ethers.getContractFactory("KYCManager");
    const kycManager = await KYCManager.deploy();
    await kycManager.deployed()

    console.log("KYCManager deployed to:", kycManager.address);

    const treeVerify = merkleTree.verify(proof, leaf, merkleRoot);
    console.log("tree.verify = ", treeVerify);

    const contractVerify = await kycManager.verifyMerkleProof(hexroot, leaf, byteproof, positions)
      
    console.log("verified = ", contractVerify);

    const { expect } = require("chai");

}

main("./test/outputMerkleTree.json");

import { decodeBase64, keccak256 } from 'ethers'
import { RP_URL } from './config'
import { startAuthentication, startRegistration } from '@simplewebauthn/browser'

const credentials = 'include'

/**
 * Modified from zerodev sdk toWebAuthnKey()
 */
export async function register(username: string) {
	// Get registration options
	const registerOptionsResponse = await fetch(`${RP_URL}/register/options`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({ username }),
		credentials,
	})
	const registerOptions = await registerOptionsResponse.json()
	console.log('registration optinos', registerOptions)

	// Start registration
	const registerCred = await startRegistration(registerOptions.options)

	const authenticatorId = registerCred.id
	console.log('authenticatorId', authenticatorId)

	// Verify registration
	const registerVerifyResponse = await fetch(`${RP_URL}/register/verify`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({
			userId: registerOptions.userId,
			username,
			cred: registerCred,
		}),
		credentials,
	})

	const registerVerifyResult = await registerVerifyResponse.json()
	if (!registerVerifyResult.verified) {
		throw new Error('Registration not verified')
	}

	const pubKey = registerCred.response.publicKey
	console.log('pubKey', pubKey)

	if (!pubKey) {
		throw new Error('No public key returned from registration credential')
	}
	if (!authenticatorId) {
		throw new Error('No authenticator id returned from registration credential')
	}

	const authenticatorIdHash = keccak256(decodeBase64URL(authenticatorId))

	const spkiDer = Buffer.from(pubKey, 'base64')
	const key = await crypto.subtle.importKey(
		'spki',
		spkiDer,
		{
			name: 'ECDSA',
			namedCurve: 'P-256',
		},
		true,
		['verify'],
	)

	// Export the key to the raw format
	const rawKey = await crypto.subtle.exportKey('raw', key)
	const rawKeyBuffer = Buffer.from(rawKey)

	// The first byte is 0x04 (uncompressed), followed by x and y coordinates (32 bytes each for P-256)
	const pubKeyX = rawKeyBuffer.subarray(1, 33).toString('hex')
	const pubKeyY = rawKeyBuffer.subarray(33).toString('hex')

	return {
		pubX: BigInt(`0x${pubKeyX}`),
		pubY: BigInt(`0x${pubKeyY}`),
		authenticatorId,
		authenticatorIdHash,
	}
}

/**
 * Modified from zerodev sdk toWebAuthnKey()
 */
export async function login(username: string) {
	// Get login options
	const loginOptionsResponse = await fetch(`${RP_URL}/login/options`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},

		credentials,
	})
	const loginOptions = await loginOptionsResponse.json()

	// Start authentication (login)
	const loginCred = await startAuthentication(loginOptions)

	const authenticatorId = loginCred.id
	console.log('authenticatorId', authenticatorId)

	// Verify authentication
	const loginVerifyResponse = await fetch(`${RP_URL}/login/verify`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({ cred: loginCred }),
		credentials,
	})

	const loginVerifyResult = await loginVerifyResponse.json()

	if (!loginVerifyResult.verification.verified) {
		throw new Error('Login not verified')
	}
	// Import the key
	const pubKey = loginVerifyResult.pubkey // Uint8Array pubkey

	console.log('pubKey', pubKey)

	if (!pubKey) {
		throw new Error('No public key returned from registration credential')
	}
	if (!authenticatorId) {
		throw new Error('No authenticator id returned from registration credential')
	}

	const authenticatorIdHash = keccak256(decodeBase64URL(authenticatorId))

	const spkiDer = Buffer.from(pubKey, 'base64')
	const key = await crypto.subtle.importKey(
		'spki',
		spkiDer,
		{
			name: 'ECDSA',
			namedCurve: 'P-256',
		},
		true,
		['verify'],
	)

	// Export the key to the raw format
	const rawKey = await crypto.subtle.exportKey('raw', key)
	const rawKeyBuffer = Buffer.from(rawKey)

	// The first byte is 0x04 (uncompressed), followed by x and y coordinates (32 bytes each for P-256)
	const pubKeyX = rawKeyBuffer.subarray(1, 33).toString('hex')
	const pubKeyY = rawKeyBuffer.subarray(33).toString('hex')

	return {
		pubX: BigInt(`0x${pubKeyX}`),
		pubY: BigInt(`0x${pubKeyY}`),
		authenticatorId,
		authenticatorIdHash,
	}
}

function decodeBase64URL(base64UrlString: string) {
	// Replace URL-specific characters and pad with '=' to match Base64 format
	let base64 = base64UrlString.replace(/-/g, '+').replace(/_/g, '/')
	while (base64.length % 4 !== 0) {
		base64 += '='
	}

	// Decode using ethers' decodeBase64 method
	return decodeBase64(base64)
}

// export async function signMessage(
// 	message: SignableMessage,
// 	chainId: number,
// 	allowCredentials?: PublicKeyCredentialRequestOptionsJSON['allowCredentials'],
// ) {
//     let messageContent: string
//     if (typeof message === "string") {
//         // message is a string
//         messageContent = message
//     } else if ("raw" in message && typeof message.raw === "string") {
//         // message.raw is a Hex string
//         messageContent = message.raw
//     } else if ("raw" in message && message.raw instanceof Uint8Array) {
//         // message.raw is a ByteArray
//         messageContent = message.raw.toString()
//     } else {
//         throw new Error("Unsupported message format")
//     }

//     // remove 0x prefix if present
//     const formattedMessage = messageContent.startsWith("0x")
//         ? messageContent.slice(2)
//         : messageContent

//     const challenge = base64FromUint8Array(
//         hexStringToUint8Array(formattedMessage),
//         true
//     )

//     // prepare assertion options
//     const assertionOptions: PublicKeyCredentialRequestOptionsJSON = {
//         challenge,
//         allowCredentials,
//         userVerification: "required"
//     }

//     // start authentication (signing)
//     const cred = await startAuthentication(assertionOptions)

//     // get authenticator data
//     const { authenticatorData } = cred.response
//     const authenticatorDataHex = uint8ArrayToHexString(
//         b64ToBytes(authenticatorData)
//     )

//     // get client data JSON
//     const clientDataJSON = atob(cred.response.clientDataJSON)

//     // get challenge and response type location
//     const { beforeType } = findQuoteIndices(clientDataJSON)

//     // get signature r,s
//     const { signature } = cred.response
//     const signatureHex = uint8ArrayToHexString(b64ToBytes(signature))
//     const { r, s } = parseAndNormalizeSig(signatureHex)

//     // encode signature
//     const encodedSignature = encodeAbiParameters(
//         [
//             { name: "authenticatorData", type: "bytes" },
//             { name: "clientDataJSON", type: "string" },
//             { name: "responseTypeLocation", type: "uint256" },
//             { name: "r", type: "uint256" },
//             { name: "s", type: "uint256" },
//             { name: "usePrecompiled", type: "bool" }
//         ],
//         [
//             authenticatorDataHex,
//             clientDataJSON,
//             beforeType,
//             BigInt(r),
//             BigInt(s),
//             isRIP7212SupportedNetwork(chainId)
//         ]
//     )
//     return encodedSignature
// }

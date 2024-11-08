<script setup lang="ts">
import { ref } from 'vue'
import { login, register, signMessage } from '@/core'

const username = ref('alice')

async function onClickRegister() {
	try {
		const { pubX, pubY, authenticatorId, authenticatorIdHash } = await register(username.value)
		console.log('register', pubX, pubY, authenticatorId, authenticatorIdHash)

		// @todo install webauthn validator module
	} catch (e) {
		console.error(e)
		alert(e)
	}
}

async function onClickLogin() {
	try {
		const { pubX, pubY, authenticatorId, authenticatorIdHash } = await login()
		console.log('login', pubX, pubY, authenticatorId, authenticatorIdHash)
	} catch (e) {
		console.error(e)
		alert(e)
	}
}

const message = ref('hello world')
async function onClickSign() {
	const signature = await signMessage(message.value)
	console.log(signature)
}
</script>

<template>
	<div class="p-5 flex flex-col gap-5">
		<div class="flex gap-2 items-center">
			<label for="username">Username</label>
			<input v-model="username" type="text" class="input" />
		</div>

		<div class="flex flex-col gap-2">
			<div class="title">Registration</div>
			<div>
				<button class="btn" @click="onClickRegister">Register</button>
			</div>
		</div>

		<div class="flex flex-col gap-2">
			<div class="title">Login</div>
			<div>
				<button class="btn" @click="onClickLogin">Login</button>
			</div>
		</div>

		<div class="flex flex-col gap-2">
			<div class="title">Sign</div>
			<div class="flex gap-2 items-center">
				<label for="username">Message</label>
				<input v-model="message" type="text" class="input" />
			</div>
			<div>
				<button class="btn" @click="onClickSign">Sign</button>
			</div>
		</div>
	</div>
</template>

<style lang="css">
.title {
	@apply text-xl;
}

.btn {
	@apply border py-1 px-3 text-base bg-teal-600 text-white rounded cursor-pointer hover:bg-teal-700 disabled:cursor-default disabled:bg-gray-600 disabled:opacity-50;
}

.input {
	@apply w-[150px] h-[27px] shadow appearance-none border rounded py-3 px-3 text-gray-700 leading-tight focus:outline-none;
}
</style>

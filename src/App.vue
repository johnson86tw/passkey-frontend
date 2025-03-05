<script setup lang="ts">
import { onMounted } from 'vue'
import { BASE_URL } from './config'

onMounted(async () => {
	const response = await fetch(BASE_URL + '/health', {
		method: 'GET',
		headers: {
			'Content-Type': 'application/json',
		},
	}).then(res => res.json())

	console.log('backend status:', response.status)
})
</script>

<template>
	<div>
		<router-view />
	</div>
</template>

<style lang="scss"></style>

<script setup lang="ts">
import { onMounted } from 'vue'

onMounted(async () => {
	const response = await fetch('http://127.0.0.1:8080' + '/health', {
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

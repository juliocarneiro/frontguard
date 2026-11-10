<template>
  <article>
    <h1>{{ user.name }}</h1>
    <div v-html="user.bio"></div>
  </article>
</template>

<script setup lang="ts">
const props = defineProps<{ token: string }>();
localStorage.setItem('authToken', props.token);
</script>

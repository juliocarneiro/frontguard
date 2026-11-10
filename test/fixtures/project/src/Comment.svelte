<script>
  export let comment;
  window.parent.postMessage({ comment }, '*');
</script>

<p>{@html comment.body}</p>

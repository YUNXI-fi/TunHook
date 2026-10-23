<script>
  import { createEventDispatcher } from 'svelte';
  export let checked = false;
  export let disabled = false;
  const dispatch = createEventDispatcher();
  function onChange() {
    dispatch('change', checked);
  }
</script>

<label class="toggle-switch">
  <input type="checkbox" bind:checked {disabled} on:change={onChange} />
  <span class="toggle-track"></span>
</label>

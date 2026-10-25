<?php
if (isset($_FILES['foto'])) {
    move_uploaded_file($_FILES['foto']['tmp_name'], __DIR__ . '/uploads/' . $_FILES['foto']['name']);
}

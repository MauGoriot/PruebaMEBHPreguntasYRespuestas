async function toggleEstado(preguntaId, estadoActual) {
    const nuevoEstado = !estadoActual;
    const url = '/Preguntas/ActualizarEstadoPregunta';
    const body = JSON.stringify({ preguntaID: preguntaId, estado: nuevoEstado });

    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: body,
        });

        if (response.ok) {
            const resultado = await response.json();
            if (resultado.success) {
                // Usamos SweetAlert2 para mostrar el mensaje
                Swal.fire({
                    icon: 'success',
                    title: 'Éxito',
                    text: resultado.message,
                    showConfirmButton: false,
                    timer: 3000,
                });

                // Actualizamos el texto en la página
                document.getElementById(`estado_${preguntaId}`).textContent = nuevoEstado ? 'Activa' : 'Inactiva';

                // Cambiar el texto del botón
                const boton = document.querySelector(`button[onclick*='toggleEstado(${preguntaId},']`);
                boton.textContent = nuevoEstado ? 'Desactivar' : 'Activar';
                boton.setAttribute('onclick', `toggleEstado(${preguntaId}, ${nuevoEstado})`);

                // Cambiar clases de botón
                if (nuevoEstado) {
                    boton.classList.remove('btn-primary');
                    boton.classList.add('btn-secondary');
                } else {
                    boton.classList.remove('btn-secondary');
                    boton.classList.add('btn-primary');
                }
            } else {
                Swal.fire({
                    icon: 'error',
                    title: 'Error',
                    text: resultado.message,
                    showConfirmButton: true,
                });
            }
        } else {
            Swal.fire({
                icon: 'error',
                title: 'Error',
                text: 'Error al realizar la solicitud.',
                showConfirmButton: true,
            });
        }
    } catch (error) {
        Swal.fire({
            icon: 'error',
            title: 'Error de red',
            text: 'Ocurrió un problema de red.',
            showConfirmButton: true,
        });
    }
}

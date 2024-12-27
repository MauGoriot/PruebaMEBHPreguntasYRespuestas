using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace CapaPresentacion.Models
{
    public class PreguntaRespuesta
    {
        public Pregunta Pregunta { get; set; }
        public List<Respuesta> Respuestas { get; set; }
    }
}
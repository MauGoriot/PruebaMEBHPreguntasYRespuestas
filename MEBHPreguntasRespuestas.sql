CREATE DATABASE PreguntasRespuestasDB
GO

USE [PreguntasRespuestasDB]
GO
/****** Object:  Table [dbo].[Preguntas]    Script Date: 26/12/2024 23:46:42 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Preguntas](
	[PreguntaID] [int] IDENTITY(1,1) NOT NULL,
	[UsuarioID] [int] NOT NULL,
	[Titulo] [nvarchar](255) NOT NULL,
	[FechaCreacion] [datetime] NULL,
	[Estado] [bit] NULL,
PRIMARY KEY CLUSTERED 
(
	[PreguntaID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Respuestas]    Script Date: 26/12/2024 23:46:42 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Respuestas](
	[RespuestaID] [int] IDENTITY(1,1) NOT NULL,
	[PreguntaID] [int] NOT NULL,
	[UsuarioID] [int] NOT NULL,
	[Contenido] [nvarchar](max) NOT NULL,
	[FechaCreacion] [datetime] NULL,
PRIMARY KEY CLUSTERED 
(
	[RespuestaID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Usuarios]    Script Date: 26/12/2024 23:46:42 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Usuarios](
	[UsuarioID] [int] IDENTITY(1,1) NOT NULL,
	[NombreUsuario] [nvarchar](50) NOT NULL,
	[Clave] [nvarchar](255) NOT NULL,
	[Rol] [varchar](50) NULL,
PRIMARY KEY CLUSTERED 
(
	[UsuarioID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY],
UNIQUE NONCLUSTERED 
(
	[NombreUsuario] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
ALTER TABLE [dbo].[Preguntas] ADD  DEFAULT (getdate()) FOR [FechaCreacion]
GO
ALTER TABLE [dbo].[Preguntas] ADD  DEFAULT ((1)) FOR [Estado]
GO
ALTER TABLE [dbo].[Respuestas] ADD  DEFAULT (getdate()) FOR [FechaCreacion]
GO
ALTER TABLE [dbo].[Usuarios] ADD  DEFAULT ('usuario') FOR [Rol]
GO
ALTER TABLE [dbo].[Preguntas]  WITH CHECK ADD FOREIGN KEY([UsuarioID])
REFERENCES [dbo].[Usuarios] ([UsuarioID])
GO
ALTER TABLE [dbo].[Respuestas]  WITH CHECK ADD FOREIGN KEY([PreguntaID])
REFERENCES [dbo].[Preguntas] ([PreguntaID])
GO
ALTER TABLE [dbo].[Respuestas]  WITH CHECK ADD FOREIGN KEY([UsuarioID])
REFERENCES [dbo].[Usuarios] ([UsuarioID])
GO
/****** Object:  StoredProcedure [dbo].[sp_ActualizarEstadoPregunta]    Script Date: 26/12/2024 23:46:42 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE PROCEDURE [dbo].[sp_ActualizarEstadoPregunta]
    @PreguntaID INT,
    @NuevoEstado BIT,
    @Mensaje NVARCHAR(255) OUTPUT
AS
BEGIN
    
    UPDATE Preguntas
    SET Estado = @NuevoEstado
    WHERE PreguntaID = @PreguntaID;

   
    IF @@ROWCOUNT > 0
    BEGIN
        
        SET @Mensaje = 'Estado de la pregunta actualizado correctamente.';
    END
    ELSE
    BEGIN
       
        SET @Mensaje = 'Error al actualizar el estado de la pregunta.';
    END
END;

GO
/****** Object:  StoredProcedure [dbo].[sp_GuardarPregunta]    Script Date: 26/12/2024 23:46:42 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE PROCEDURE [dbo].[sp_GuardarPregunta]
    @UsuarioID INT,
    @Titulo NVARCHAR(255),
    @Mensaje NVARCHAR(255) OUTPUT  
AS
BEGIN

    INSERT INTO Preguntas (UsuarioID, Titulo)
    VALUES (@UsuarioID, @Titulo); 


    IF @@ROWCOUNT > 0
    BEGIN
        SET @Mensaje = 'Pregunta publicada correctamente.';
    END
    ELSE
    BEGIN
        SET @Mensaje = 'Error al guardar la pregunta.';
    END
END;
GO
/****** Object:  StoredProcedure [dbo].[sp_InsertarRespuesta]    Script Date: 26/12/2024 23:46:42 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE PROCEDURE [dbo].[sp_InsertarRespuesta]
    @PreguntaID INT,
    @UsuarioID INT,
    @Contenido NVARCHAR(MAX),
    @Mensaje NVARCHAR(255) OUTPUT
AS
BEGIN

    IF EXISTS (SELECT 1 FROM Preguntas WHERE PreguntaID = @PreguntaID AND Estado = 1)
    BEGIN
        
        INSERT INTO Respuestas (PreguntaID, UsuarioID, Contenido, FechaCreacion)
        VALUES (@PreguntaID, @UsuarioID, @Contenido, GETDATE());
        
        SET @Mensaje = 'Respuesta publicada correctamente.';
    END
END

GO
/****** Object:  StoredProcedure [dbo].[sp_RegistrarUsuario]    Script Date: 26/12/2024 23:46:42 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE procedure [dbo].[sp_RegistrarUsuario](
@NombreUsuario varchar(100),
@Clave nvarchar(500),
@Registro bit output,
@Mensaje nvarchar(100) output
)
as
begin
	if (not exists(select NombreUsuario from Usuarios where NombreUsuario = @NombreUsuario))
	begin
		insert into Usuarios(NombreUsuario,Clave) values (@NombreUsuario,@Clave)
		set @Registro = 1
		set @mensaje = 'Usuario registrado'
	end
	else
	begin
		set @Registro = 0
		set @Mensaje = 'Usuario ya existe'
	end
end
GO
/****** Object:  StoredProcedure [dbo].[sp_ValidarUsuario]    Script Date: 26/12/2024 23:46:42 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE PROCEDURE [dbo].[sp_ValidarUsuario]
    @NombreUsuario NVARCHAR(100),
    @Clave NVARCHAR(500)
AS
BEGIN
    IF EXISTS (SELECT 1 FROM Usuarios WHERE NombreUsuario = @NombreUsuario AND Clave = @Clave)
    BEGIN
        SELECT UsuarioID, NombreUsuario, Rol 
        FROM Usuarios 
        WHERE NombreUsuario = @NombreUsuario AND Clave = @Clave;
    END
    ELSE
    BEGIN
        SELECT NULL AS UsuarioID, NULL AS NombreUsuario, NULL AS Rol;
    END
END

GO

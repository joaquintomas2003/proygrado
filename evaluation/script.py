#!/usr/bin/env python3

def procesar_archivo(archivo_entrada, archivo_salida):
    """
    Procesa un archivo con formato 'X | Y' donde Y es hexadecimal.
    Cuenta las ocurrencias de cada valor Y (convertido a decimal) y 
    guarda el resultado en un CSV.
    
    Args:
        archivo_entrada: Ruta del archivo .txt de entrada
        archivo_salida: Ruta del archivo .csv de salida
    """
    
    # Etapa 1 y 2: Leer archivo, extraer valores hex y convertir a decimal
    print("Leyendo archivo y procesando valores...")
    valores_decimales = []
    
    with open(archivo_entrada, 'r', encoding='utf-8') as f:
        for linea in f:
            linea = linea.strip()
            if '|' in linea:
                # Eliminar "X | " y quedarse solo con Y
                partes = linea.split('|')
                valor_hex = partes[1].strip()
                
                # Convertir de hexadecimal a decimal
                valor_decimal = int(valor_hex, 16)
                valores_decimales.append(valor_decimal)
    
    print(f"Total de líneas procesadas: {len(valores_decimales)}")
    
    # Etapa 3: Contar ocurrencias y eliminar duplicados
    print("Contando ocurrencias...")
    resultados = []
    valores_procesados = set()
    
    for valor in valores_decimales:
        # Si ya procesamos este valor, lo saltamos
        if valor in valores_procesados:
            continue
        
        # Contar cuántas veces aparece este valor
        ocurrencias = valores_decimales.count(valor)
        resultados.append((valor, ocurrencias))
        
        # Marcar como procesado para no volver a contarlo
        valores_procesados.add(valor)
    
    print(f"Valores únicos encontrados: {len(resultados)}")
    
    # Escribir resultados en CSV
    print(f"Escribiendo resultados en {archivo_salida}...")
    with open(archivo_salida, 'w', encoding='utf-8') as f:
        for valor, ocurrencias in resultados:
            f.write(f"{valor}, {ocurrencias}\n")
    
    print("¡Proceso completado!")
    
    # Mostrar resumen
    print("\n--- Resumen ---")
    for valor, ocurrencias in resultados[:10]:  # Mostrar primeros 10
        print(f"Valor {valor}: {ocurrencias} ocurrencia(s)")
    if len(resultados) > 10:
        print(f"... y {len(resultados) - 10} valores más")


if __name__ == "__main__":
    # Configuración de archivos
    archivo_entrada = "entrada.txt"
    archivo_salida = "salida.csv"
    
    try:
        procesar_archivo(archivo_entrada, archivo_salida)
    except FileNotFoundError:
        print(f"Error: No se encontró el archivo '{archivo_entrada}'")
    except Exception as e:
        print(f"Error durante el procesamiento: {e}")

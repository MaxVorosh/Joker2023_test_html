package me.markoutte.joker.parse.step1

import org.apache.commons.cli.DefaultParser
import org.apache.commons.cli.Options
import java.io.File
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import java.net.URLClassLoader
import java.nio.ByteBuffer
import java.nio.charset.Charset
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.StandardOpenOption
import java.util.concurrent.TimeUnit
import kotlin.random.Random
import kotlin.random.Random.Default.nextInt


fun create_str(strLen: Int): String {
    var b = ""
    for (i in 1..strLen) {
        b += Char(nextInt(1, 256))
    }
    return b
}

fun create_list(type: String, strLen: Int, listLen: Int): String {
    val size = nextInt(1, listLen)
    var b = "<$type>"
    for (i in 1..size) {
        val content = create_str(strLen)
        b += "<li>$content</li>"
    }
    b += "</$type>"
    return b
}
fun create_start_entity(strLen: Int, listLen: Int): String {
    var b = create_str(strLen)
    val options = arrayOf("ol", "ul", "a", "img", "definition", "None")
    val type = nextInt(0, options.size)
    if (type <= 1) {
        b = create_list(options[type], strLen, listLen)
    }
    else if (type == 2) {
        val link = create_str(strLen)
        b = "<a href=\"$link\">$b</a>"
    }
    else if (type == 3) {
        val source = create_str(strLen)
        b = "<img src=\"$source\">$b</img>"
    }
    else if (type == 4) {
        val dfn = create_str(strLen)
        val dd = create_str(strLen)
        b = "<definition><dfn>$dfn</dfn><dd>$dd</dd></definition>"
    }
    return b
}

fun wrap(doc: String): String {
    val tag_names = arrayOf("div", "p", "address", "b", "cite", "samp", "del", "em",
        "legend", "i", "ins", "q", "s", "small", "h1", "h2", "h3", "h4", "h5", "h6",
        "fieldset", "strong", "sup", "sub", "u", "ins", "mark", "pre", "span")
    val simple_tags: MutableList<Pair<String, String>> = arrayListOf()
    for (tag in tag_names) {
        simple_tags.add(Pair("<$tag>", "</$tag>"))
    }
    val tag_pos = nextInt(0, simple_tags.size)
    return simple_tags[tag_pos].first + doc + simple_tags[tag_pos].second
}

fun create_entity(depth: Int, strLen: Int, listLen: Int, entityCnt: Int): String {
    val spec_tags = arrayOf("<br>", "<hr>")
    var currentEntityCnt = entityCnt
    if (depth == 0) {
        return create_start_entity(strLen, listLen)
    }
    var doc = create_start_entity(strLen, listLen)
    for (i in 1..nextInt(1, depth + 1)) {
        val type = nextInt(0, 2)
        if (type == 0 || currentEntityCnt == 0) {
            doc = wrap(doc)
        }
        else {
            currentEntityCnt -= 1
            doc += create_entity(depth - i, strLen, listLen, currentEntityCnt)
        }
        val spec = nextInt(0, 10)
        if (spec < spec_tags.size) {
            doc += spec_tags[spec]
        }
    }
    return doc
}

fun generate_html(depth: Int, strLen: Int, listLen: Int, entityCnt: Int): String {
    var doc = create_entity(depth, strLen, listLen, entityCnt)
    for (i in 1..nextInt(0, entityCnt)) {
        doc += create_entity(depth, strLen, listLen, entityCnt)
    }
    val title = create_str(strLen)
    val descriptionContent = create_str(strLen)
    val authorContent = create_str(strLen)
    val generatorContent = create_str(strLen)
    val keywordsContent = create_str(strLen)
    val AppNameContent = create_str(strLen)
    return "<!doctype html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\">" +
            "<meta name=\"description\" content=\"$descriptionContent\">" +
            "<meta name=\"author\" content=\"$authorContent\">" +
            "<meta name=\"application name\" content=\"$AppNameContent\">" +
            "<meta name=\"generator\" content=\"$generatorContent\">" +
            "<meta name=\"keywords\" content=\"$keywordsContent\">" +
            "<title>$title</title>\n</head>\n<body>$doc</body>\n</html>"
}
fun main(args: Array<String>) {
    val options = Options().apply {
        addOption("c", "class", true, "Java class fully qualified name")
        addOption("m", "method", true, "Method to be tested")
        addOption("cp", "classpath", true, "Classpath with libraries")
        addOption("t", "timeout", true, "Maximum time for fuzzing in seconds")
        addOption("s", "seed", true, "The source of randomness")
    }
    val parser = DefaultParser().parse(options, args)
    val className = parser.getOptionValue("class")
    val methodName = parser.getOptionValue("method")
    val classPath = parser.getOptionValue("classpath")
    val timeout = parser.getOptionValue("timeout")?.toLong() ?: 10L
    val seed = parser.getOptionValue("seed")?.toInt() ?: nextInt()
    val random = Random(seed)

    println("Running: $className.$methodName) with seed = $seed")
    val errors = mutableSetOf<String>()
    val b = ByteArray(300)
    val start = System.nanoTime()

    val javaMethod = try {
        loadJavaMethod(className, methodName, classPath)
    } catch (t: Throwable) {
        println("Method $className#$methodName is not found")
        return
    }

    while(System.nanoTime() - start < TimeUnit.SECONDS.toNanos(timeout)) {
        val buffer = b.apply(random::nextBytes)
        val inputValue = generate_html(30, 10, 10, 10)
//        println(inputValue)
//        println()
//        println("---------")
//        println()
        val inputValuesString = "${javaMethod.name}: $inputValue"
        try {
            javaMethod.invoke(null, inputValue)
        } catch (e: InvocationTargetException) {
            if (errors.add(e.targetException::class.qualifiedName!!)) {
                val errorName = e.targetException::class.simpleName
                println("New error found: $errorName")
                val path = Paths.get("report$errorName.txt")
                Files.write(path, listOf(
                    "${e.targetException.stackTraceToString()}\n",
                    "$inputValuesString\n",
                    "${buffer.contentToString()}\n",
                ))
                Files.write(path, buffer, StandardOpenOption.APPEND)
                println("Saved to: ${path.fileName}")
            }
        }
    }

    println("Errors found: ${errors.size}")
    println("Time elapsed: ${TimeUnit.NANOSECONDS.toMillis(
        System.nanoTime() - start
    )} ms")
}

fun loadJavaMethod(className: String, methodName: String, classPath: String): Method {
    val libraries = classPath
        .split(File.pathSeparatorChar)
        .map { File(it).toURI().toURL() }
        .toTypedArray()
    val classLoader = URLClassLoader(libraries)
    val javaClass = classLoader.loadClass(className)
    val javaMethod = javaClass.declaredMethods.first {
        "${it.name}(${it.parameterTypes.joinToString(",") {
                c -> c.typeName
        }})" == methodName
    }
    return javaMethod
}

fun generateInputValues(method: Method, data: ByteArray): Array<Any> {
    val buffer = ByteBuffer.wrap(data)
    val parameterTypes = method.parameterTypes
    return Array(parameterTypes.size) {
        when (parameterTypes[it]) {
            Int::class.java -> buffer.get().toInt()
            IntArray::class.java -> IntArray(buffer.get().toUByte().toInt()) {
                buffer.get().toInt()
            }
            String::class.java -> String(ByteArray(
                buffer.get().toUByte().toInt() + 1
            ) {
                buffer.get()
            }, Charset.forName("koi8"))
            else -> error("Cannot create value of type ${parameterTypes[it]}")
        }
    }
}
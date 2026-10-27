<?php

// Capture diagnostics without bootstrapping the site or writing application logs.
namespace Nexus\Imdb {
    function do_log($message, $level = 'info'): void
    {
        $GLOBALS['imdbTestLogs'][] = [$message, $level];
    }
}
namespace Nexus {
    function do_log($message, $level = 'info'): void
    {
        $GLOBALS['imdbTestLogs'][] = [$message, $level];
    }
}
namespace Nexus\Database {
    // The test uses no translated cache variants and must not query the site DB.
    function get_langfolder_list(): array
    {
        return [];
    }
}

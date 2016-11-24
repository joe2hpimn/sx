$(document).ready(function () {
    var url = window.location;
    // Will only work if string in href matches with location
    $('ul.nav a[href="' + url + '"]').parent().addClass('active');

    // Will also work for relative and absolute hrefs
    $('ul.nav a').filter(function () {
        return this.href == url;
    }).parent().addClass('active').parent().parent().addClass('active');
});

// Same as the above but automatically stops after two seconds
Ladda.bind( '.ladda-button', { timeout: 1300 } );

$(function() {
    $('.ladda-button').on('click', function() {
        $('.home-main-section__inputs').addClass('animated shake').one('webkitAnimationEnd mozAnimationEnd MSAnimationEnd oanimationend animationend',
            function() {
            $(this).removeClass('animated shake');
        });
    });
});

$('.carousel').carousel({
    interval: 3000
});

$('.carousel-2').carousel({
    interval: 2500,
    pause: "false"
});

$('pre code').each(function(i, block) {
    hljs.highlightBlock(block);
});

$(function() {
    $('.dropdown-toggle').hover(function() {
        $('.mega-dropdown-menu').stop(true).fadeIn(300);
    }, function() {
        $('.mega-dropdown-menu').stop(true).fadeOut(300);
    });
});

$(function() {
    $(window).scroll(function() {
        var scroll = $(window).scrollTop();

        if (scroll >= 50) {
            $(".navbar").removeClass('fade-transparent').addClass("fade-background");
        } else {
            $(".navbar").removeClass("fade-background").addClass('fade-transparent');
        }
    });
});

if ($('.back-to-top').length) {
    var scrollTrigger = 100, // px
        backToTop = function () {
            var scrollTop = $(window).scrollTop();
            if (scrollTop > scrollTrigger) {
                $('.back-to-top').addClass('show');
            } else {
                $('.back-to-top').removeClass('show');
            }
        };
    backToTop();
    $(window).on('scroll', function () {
        backToTop();
    });
    $('.back-to-top').on('click', function (e) {
        e.preventDefault();
        $('html,body').animate({
            scrollTop: 0
        }, 700);
    });
}

var $root = $('html, body');
$('a').click(function() {
    var href = $.attr(this, 'href');
    $root.animate({
        scrollTop: $(href).offset().top
    }, 500, function () {
        window.location.hash = href;
    });
    return false;
});
